# src/checks/password_check.py
"""
Password scanner for Chromium-family browsers + Wi-Fi profiles (Windows).

- Discovers Chromium-based browsers/profiles and extracts saved logins.
- Decrypts Chrome password blobs (DPAPI and AES-GCM v10/v11).
- Optionally checks breach counts via HaveIBeenPwned if hibp_helper is available.
- Never writes plaintext passwords to disk; keeps plaintext only in-memory briefly.
"""

import os
import sys
import json
import base64
import sqlite3
import shutil
import subprocess
import hashlib
from pathlib import Path
from typing import List, Dict, Optional

# Add the src folder to sys.path if running standalone
sys.path.append(str(Path(__file__).resolve().parents[2]))

# ---- Optional dependencies ----
try:
    import win32crypt  # pywin32 (Windows DPAPI)
    def dpapi_unprotect(encrypted_bytes: bytes) -> bytes:
        return win32crypt.CryptUnprotectData(encrypted_bytes, None, None, None, 0)[1]
except Exception:
    dpapi_unprotect = None  # we'll return None when DPAPI isn't available

# AES-GCM support (pycryptodome)
try:
    from Crypto.Cipher import AES
except Exception:
    AES = None

# Color output (optional)
try:
    from colorama import init as _colorama_init, Fore, Style
    _colorama_init(autoreset=True)
    def color(text, c): return f"{c}{text}{Style.RESET_ALL}"
except Exception:
    Fore = None
    def color(text, c=None): return text

# Try to import hibp helper (placed at src/hibp_helper.py)
hibp_available = True
try:
    # Try common import paths
    try:
        from hibp_helper import hibp_check_hash, sha1_hex  # if running from src/
    except Exception:
        from src.hibp_helper import hibp_check_hash, sha1_hex  # if running as package
except Exception:
    hibp_available = False
    def sha1_hex(s): return hashlib.sha1(s.encode('utf-8')).hexdigest().upper()
    hibp_check_hash = None

# ---------------------------
# Chromium browser discovery
# ---------------------------
CHROMIUM_BROWSERS = [
    ("Google\\Chrome", "Google Chrome"),
    ("Microsoft\\Edge", "Microsoft Edge"),
    ("BraveSoftware\\Brave-Browser", "Brave"),
    ("Vivaldi", "Vivaldi"),
    ("Opera Software\\Opera Stable", "Opera"),
    ("Chromium", "Chromium"),
]

def find_chromium_login_dbs() -> List[Dict]:
    """
    Discover Chromium-based browser profiles on Windows.
    Returns a list of dicts {browser, profile, login_db (Path), local_state (Path)}.
    """
    results = []
    local_app = os.environ.get("LOCALAPPDATA")
    if not local_app:
        return results
    base = Path(local_app)
    for folder, friendly in CHROMIUM_BROWSERS:
        user_data_base = base / folder / "User Data"
        if not user_data_base.exists():
            continue
        # Gather profile folders (Default + Profile X)
        candidates = []
        candidates.append(user_data_base / "Default")
        for p in user_data_base.iterdir():
            if p.is_dir() and (p.name.startswith("Profile") or p.name.startswith("Guest Profile") or p.name.startswith("Person")):
                candidates.append(p)
        seen = set()
        for profile_dir in candidates:
            login_db = profile_dir / "Login Data"
            local_state = user_data_base / "Local State"
            if login_db.exists() and str(login_db.resolve()) not in seen:
                results.append({
                    "browser": friendly,
                    "profile": profile_dir.name,
                    "login_db": login_db,
                    "local_state": local_state
                })
                seen.add(str(login_db.resolve()))
    return results

# ---------------------------
# Chrome master key + decryption
# ---------------------------
def get_chrome_master_key_for_user_data(user_data_dir: Path) -> Optional[bytes]:
    """
    Given a browser 'User Data' folder Path, read Local State and return the decrypted master key (bytes).
    Returns None if not found or decryption fails.
    """
    local_state_path = user_data_dir / "Local State"
    if not local_state_path.exists():
        return None
    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
        encrypted_key_b64 = local_state.get("os_crypt", {}).get("encrypted_key")
        if not encrypted_key_b64:
            return None
        encrypted_key = base64.b64decode(encrypted_key_b64)
        # Windows DPAPI prefix
        if encrypted_key.startswith(b"DPAPI"):
            encrypted_key = encrypted_key[5:]
        if dpapi_unprotect is None:
            return None
        master_key = dpapi_unprotect(encrypted_key)
        return master_key
    except Exception:
        return None

def decrypt_chrome_value(enc_value: bytes, master_key: Optional[bytes] = None) -> Optional[str]:
    """
    Decrypt a Chrome encrypted blob.
    Supports DPAPI-only (older) and v10/v11 AES-GCM (newer) formats.
    Returns plaintext string or None if decryption fails.
    """
    if not enc_value:
        return None
    # v10/v11 format: b'v10' + 12-byte nonce + ciphertext + 16-byte tag
    try:
        if enc_value.startswith(b"v10") or enc_value.startswith(b"v11"):
            if master_key is None or AES is None:
                return None
            try:
                nonce = enc_value[3:15]  # 12 bytes
                ct_and_tag = enc_value[15:]
                if len(ct_and_tag) < 16:
                    return None
                ciphertext = ct_and_tag[:-16]
                tag = ct_and_tag[-16:]
                cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                return plaintext.decode("utf-8", errors="ignore")
            except Exception:
                return None
        else:
            # DPAPI-protected blob
            if dpapi_unprotect is None:
                return None
            try:
                decrypted = dpapi_unprotect(enc_value)
                if decrypted:
                    return decrypted.decode("utf-8", errors="ignore")
            except Exception:
                return None
    except Exception:
        return None

# ---------------------------
# Multi-browser extraction
# ---------------------------
def extract_all_chromium_logins(limit_per_profile: int = 200) -> List[Dict]:
    """
    Discover and extract saved logins from all Chromium-based browsers and profiles.
    Returns list of dicts:
      {
        "browser": friendly_name,
        "profile": profile_name,
        "origin": origin_url,
        "username": username,
        "password": plaintext_or_None
      }
    """
    found = find_chromium_login_dbs()
    all_creds = []
    for item in found:
        browser = item["browser"]
        profile = item["profile"]
        login_db = item["login_db"]
        user_data_dir = login_db.parent.parent  # ...\<Browser>\User Data
        # Attempt to get master key from this user_data_dir
        master_key = get_chrome_master_key_for_user_data(user_data_dir)
        tmp_name = f"login_data_tmp_{browser.replace(' ','_')}_{profile}.db"
        tmp_db = Path.cwd() / "data" / tmp_name
        try:
            # Copy DB to temp to avoid lock
            shutil.copy2(login_db, tmp_db)
            conn = sqlite3.connect(str(tmp_db))
            cur = conn.cursor()
            cur.execute("SELECT origin_url, username_value, password_value FROM logins")
            rows = cur.fetchall()[:limit_per_profile]
            for origin, username, pwd_blob in rows:
                if not username:
                    continue
                pwd = None
                if isinstance(pwd_blob, (bytes, bytearray)):
                    pwd = decrypt_chrome_value(pwd_blob, master_key=master_key)
                else:
                    try:
                        pwd = str(pwd_blob)
                    except:
                        pwd = None
                all_creds.append({
                    "browser": browser,
                    "profile": profile,
                    "origin": origin,
                    "username": username,
                    "password": pwd
                })
            conn.close()
        except Exception:
            # skip profile on failure
            pass
        finally:
            try:
                if tmp_db.exists():
                    tmp_db.unlink()
            except Exception:
                pass
    return all_creds

# ---------------------------
# Wi-Fi extraction (Windows)
# ---------------------------
def extract_wifi_passwords() -> List[Dict]:
    """
    Extract stored Wi-Fi SSIDs and keys (requires admin for key=clear to return password).
    Returns list of {"ssid": ssid, "password": password_or_None}
    """
    profiles = []
    try:
        res = subprocess.run(["netsh", "wlan", "show", "profiles"], capture_output=True, text=True, timeout=10)
        out = res.stdout
        for line in out.splitlines():
            line = line.strip()
            # localized outputs exist; check for ':' and plausible profile lines
            if ":" in line and ("All User Profile" in line or "Perfil de todos los usuarios" in line or line.lower().startswith("profile")):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    name = parts[1].strip()
                    if not name:
                        continue
                    # show profile with key
                    r2 = subprocess.run(["netsh", "wlan", "show", "profile", name, "key=clear"], capture_output=True, text=True, timeout=10)
                    key = None
                    for l in r2.stdout.splitlines():
                        if "Key Content" in l or "Contenido de la clave" in l:
                            kparts = l.split(":", 1)
                            if len(kparts) == 2:
                                key = kparts[1].strip()
                                break
                    profiles.append({"ssid": name, "password": key})
    except Exception:
        pass
    return profiles

# ---------------------------
# High-level scan orchestrator
# ---------------------------
def run_password_scan(limit_per_profile: int = 200, include_wifi: bool = True) -> Dict:
    """
    Runs the scan automatically (Chromium + optional Wi-Fi) and returns structured results:
    {
        "results": [...],
        "summary": {"total": N, "compromised": M},
        "top_compromised": [...]
    }
    """
    print("Scanning saved Chromium-family browser passwords{} on this machine...".format(" and Wi-Fi keys" if include_wifi else ""))
    print("Plaintext passwords will NOT be sent to any server; only SHA-1 prefixes are used for lookup (k-anonymity).")

    results = []
    cache = None
    if hibp_available:
        try:
            cache = None  # hibp helper will load its own cache if needed
        except Exception:
            cache = None

    # Chromium logins
    print("\nScanning Chromium-family browser saved passwords...")
    creds = extract_all_chromium_logins(limit_per_profile=limit_per_profile)
    for c in creds:
        pwd = c.get("password")
        breach_count = None
        risk = "Unknown"
        if pwd:
            sha = sha1_hex(pwd)
            if hibp_available and hibp_check_hash:
                try:
                    breach_count = hibp_check_hash(sha, cache=None)
                except Exception:
                    breach_count = None
            else:
                breach_count = None
            if breach_count is None:
                risk = "Unknown"
            elif breach_count == 0:
                risk = "Low"
            elif breach_count < 100:
                risk = "Medium"
            else:
                risk = "High"
        else:
            risk = "NoPassword"
        entry = {
            "source": "chrome",
            "browser": c.get("browser"),
            "profile": c.get("profile"),
            "origin": c.get("origin"),
            "username": c.get("username"),
            "breach_count": breach_count,
            "risk": risk
        }
        results.append(entry)
        # print line
        if Fore:
            if risk == "High":
                rtxt = color("HIGH", Fore.RED)
            elif risk == "Medium":
                rtxt = color("MED", Fore.YELLOW)
            elif risk == "Low":
                rtxt = color("LOW", Fore.GREEN)
            elif risk == "NoPassword":
                rtxt = color("NO-PWD", Fore.WHITE)
            else:
                rtxt = color("UNK", Fore.WHITE)
            print(f"[{c.get('browser')}/{c.get('profile')}] {c.get('origin')} ({c.get('username')}) — {rtxt} — breaches: {breach_count}")
        else:
            print(f"[{c.get('browser')}/{c.get('profile')}] {c.get('origin')} ({c.get('username')}) — risk: {risk} — breaches: {breach_count}")

    # Wi-Fi (included by default)
    if include_wifi:
        print("\nScanning Wi-Fi profiles (requires admin for key=clear)...")
        wifi = extract_wifi_passwords()
        for w in wifi:
            pwd = w.get("password")
            breach_count = None
            risk = "Unknown"
            if pwd:
                sha = sha1_hex(pwd)
                if hibp_available and hibp_check_hash:
                    try:
                        breach_count = hibp_check_hash(sha, cache=None)
                    except Exception:
                        breach_count = None
                else:
                    breach_count = None
                if breach_count is None:
                    risk = "Unknown"
                elif breach_count == 0:
                    risk = "Low"
                elif breach_count < 100:
                    risk = "Medium"
                else:
                    risk = "High"
            else:
                risk = "NoPassword"
            results.append({
                "source": "wifi",
                "ssid": w.get("ssid"),
                "breach_count": breach_count,
                "risk": risk
            })
            if Fore:
                tag = color(risk, Fore.RED if risk=="High" else (Fore.YELLOW if risk=="Medium" else (Fore.GREEN if risk=="Low" else Fore.WHITE)))
                print(f"[wifi] {w.get('ssid')} — {tag} — breaches: {breach_count}")
            else:
                print(f"[wifi] {w.get('ssid')} — risk: {risk} — breaches: {breach_count}")

    # Summary
    compromised = [r for r in results if isinstance(r.get("breach_count"), int) and r["breach_count"] > 0]
    print("\nScan complete.")
    print(f"Total credentials scanned: {len(results)}")
    print(f"Compromised credentials: {len(compromised)}")
    if compromised:
        print("Top compromised items:")
        for c in sorted(compromised, key=lambda x: (x.get("breach_count") or 0), reverse=True)[:5]:
            if c["source"] == "chrome":
                print(f"  - [chrome] {c['origin']} ({c['username']}) — {c['breach_count']} breaches")
            else:
                print(f"  - [wifi] {c.get('ssid')} — {c['breach_count']} breaches")

    # Build structured return for programmatic consumption
    top_compromised = sorted(compromised, key=lambda x: (x.get("breach_count") or 0), reverse=True)[:5]
    summary = {"total": len(results), "compromised": len(compromised)}
    return {"results": results, "summary": summary, "top_compromised": top_compromised}

# ---------------------------
# Module CLI
# ---------------------------
def _cli_main():
    # Simple wrapper to run scan from command line
    include_wifi = True
    if len(sys.argv) > 1 and sys.argv[1] in ("--no-wifi",):
        include_wifi = False
    print("Password breach scanner (Chromium-family + optional Wi-Fi).")
    if not hibp_available:
        print("Note: HIBP helper not available — breach counts will not be retrieved. Add src/hibp_helper.py to enable HIBP checks.")
    run_password_scan(include_wifi=include_wifi)

if __name__ == "__main__":
    _cli_main()
