# src/checks/permissions_check.py
"""
Full Permissions Audit (Windows) - Smart, multi-metric permission & privilege scanner.

Features:
- Enumerates installed programs (HKLM & HKCU uninstall keys) with DisplayName, Publisher,
  Version, InstallLocation / DisplayIcon where available.
- Enumerates startup items (startup folders & Run/RunOnce registry keys).
- Reads Windows capability consent store (webcam/microphone) to identify apps granted camera/mic.
- Detects processes with active network sockets (netstat -> PID -> process name).
- Attempts Authenticode signature check via PowerShell for discovered executable paths.
- Computes a weighted multi-factor score and assigns LOW / MEDIUM / HIGH risk with specific reasons.
- Color-coded CLI output and top-risks summary sorted by urgency.
Notes:
- Designed to run without admin; when data is inaccessible, entries are marked 'restricted' and accounted for.
- Runs reasonably fast on a typical dev machine (a few seconds) — avoids heavy scanning.
"""

from __future__ import annotations
import os
import re
import sys
import subprocess
import json
import shlex
from pathlib import Path
from typing import List, Dict, Optional, Tuple

# Windows-only helper modules are optional; the code uses subprocess/PowerShell where needed.
try:
    import winreg
except Exception:
    winreg = None

# Color output (optional)
try:
    from colorama import init as _colorama_init, Fore, Style
    _colorama_init(autoreset=True)
    def color(text: str, c: str) -> str:
        return f"{c}{text}{Style.RESET_ALL}"
except Exception:
    Fore = None
    def color(text: str, c: str) -> str:
        return text

# ---------------------------
# Utilities
# ---------------------------
def safe_subprocess(cmd: List[str], timeout: int = 8) -> Tuple[int, str, str]:
    """Run subprocess and return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)

def run_powershell(ps_cmd: str, timeout: int = 12) -> Tuple[int, str, str]:
    """Run a PowerShell command and return (rc, stdout, stderr)."""
    # Use -NoProfile -NonInteractive to keep it light
    cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd]
    return safe_subprocess(cmd, timeout=timeout)

def extract_exe_from_command(cmd: Optional[str]) -> Optional[str]:
    """
    Try to extract an exe absolute path from a command/registry value.
    Handles quoted paths and common patterns.
    """
    if not cmd:
        return None
    # If value like '"C:\Program Files\App\app.exe" --arg', extract quoted path
    m = re.search(r'"([^"]+\.exe)"', cmd, flags=re.IGNORECASE)
    if m:
        return m.group(1)
    # Else try first token that ends with .exe
    tokens = shlex.split(cmd, posix=False)
    for t in tokens:
        if t.lower().endswith(".exe"):
            # remove surrounding quotes/backslashes
            return t.strip('"')
    # try simple regex for path-like text
    m2 = re.search(r'([A-Za-z]:\\[^\s"]+\.exe)', cmd)
    if m2:
        return m2.group(1)
    return None

# ---------------------------
# Registry scans
# ---------------------------
def get_installed_programs() -> List[Dict]:
    """
    Read installed programs from registry (HKLM & HKCU).
    Tries to capture DisplayName, DisplayVersion, Publisher, InstallLocation, DisplayIcon.
    Marks 'restricted' if a registry key cannot be opened.
    """
    programs = []
    if not winreg:
        return programs

    uninstall_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    for hive, path in uninstall_paths:
        try:
            with winreg.OpenKey(hive, path) as hk:
                i = 0
                while True:
                    try:
                        sub = winreg.EnumKey(hk, i)
                    except OSError as e:
                        # 259 = no more data
                        if getattr(e, "winerror", None) == 259:
                            break
                        break
                    i += 1
                    subpath = f"{path}\\{sub}"
                    try:
                        with winreg.OpenKey(hive, subpath) as sk:
                            def q(name):
                                try:
                                    v, _ = winreg.QueryValueEx(sk, name)
                                    return v
                                except Exception:
                                    return None
                            name = q("DisplayName") or sub
                            version = q("DisplayVersion")
                            publisher = q("Publisher")
                            installloc = q("InstallLocation")
                            displayicon = q("DisplayIcon")
                            # Some DisplayIcon contain ,0 or args; extract exe
                            exe = extract_exe_from_command(displayicon) or (extract_exe_from_command(installloc) if installloc else None)
                            programs.append({
                                "name": name,
                                "version": version,
                                "publisher": publisher,
                                "install_location": installloc,
                                "displayicon": displayicon,
                                "exe_path": exe,
                                "restricted": False,
                                "source": f"Registry: {hive}\\{path}"
                            })
                    except PermissionError:
                        programs.append({
                            "name": sub,
                            "version": None,
                            "publisher": None,
                            "install_location": None,
                            "displayicon": None,
                            "exe_path": None,
                            "restricted": True,
                            "source": f"Registry: {hive}\\{path} (restricted)"
                        })
        except FileNotFoundError:
            continue
        except PermissionError:
            # entire uninstall key restricted
            programs.append({
                "name": f"{path}",
                "version": None,
                "publisher": None,
                "install_location": None,
                "displayicon": None,
                "exe_path": None,
                "restricted": True,
                "source": f"Registry: {hive}\\{path} (restricted)"
            })
    return programs

def get_startup_programs() -> List[Dict]:
    """
    Enumerate startup entries:
    - User & common startup folders (files/shortcuts)
    - Registry Run/RunOnce for HKCU and HKLM
    Returns entries with 'command' where available and 'exe_path' extracted when possible.
    """
    results = []
    # startup folders
    user_sf = Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup"
    common_sf = Path(os.environ.get("PROGRAMDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup"
    for folder, tag in [(user_sf, "User Startup Folder"), (common_sf, "Common Startup Folder")]:
        if folder.exists():
            for f in folder.iterdir():
                try:
                    if f.is_file():
                        cmd = str(f)
                        exe = None
                        if f.suffix.lower() in (".lnk",):
                            # For .lnk we won't resolve link binary here (would require pylnk or COM). Try reading name only.
                            exe = None
                        elif f.suffix.lower() == ".exe":
                            exe = str(f)
                        results.append({
                            "name": f.stem,
                            "command": cmd,
                            "exe_path": exe,
                            "source": tag,
                            "restricted": False,
                            "admin_required": (tag == "Common Startup Folder")
                        })
                except Exception:
                    continue

    # registry autorun keys
    autorun_keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM Run 32bit"),
    ]
    if winreg:
        for hive, path, tag in autorun_keys:
            try:
                with winreg.OpenKey(hive, path) as k:
                    i = 0
                    while True:
                        try:
                            name, val, _ = winreg.EnumValue(k, i)
                        except OSError as e:
                            if getattr(e, "winerror", None) == 259:
                                break
                            break
                        i += 1
                        exe = extract_exe_from_command(val)
                        results.append({
                            "name": name,
                            "command": val,
                            "exe_path": exe,
                            "source": tag,
                            "restricted": False,
                            "admin_required": ("HKLM" in tag)
                        })
            except FileNotFoundError:
                continue
            except PermissionError:
                results.append({
                    "name": path,
                    "command": None,
                    "exe_path": None,
                    "source": f"{tag} (restricted)",
                    "restricted": True,
                    "admin_required": ("HKLM" in tag)
                })
    return results

# ---------------------------
# Capability (camera/microphone) mapping
# ---------------------------
def get_capability_consents() -> Dict[str, List[str]]:
    """
    Read capability consent entries from HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore
    This registry area stores per-capability acceptance for UWP apps and some app containers.
    We'll parse 'webcam' and 'microphone' entries and collect which AppIDs/packages have Consent=Allow.
    Returns a dict {capability: [appids...]}
    """
    caps = {"webcam": [], "microphone": []}
    if not winreg:
        return caps
    base_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
    for cap in ["webcam", "microphone"]:
        cap_path = f"{base_path}\\{cap}"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, cap_path) as key:
                i = 0
                while True:
                    try:
                        sub = winreg.EnumKey(key, i)
                    except OSError:
                        break
                    i += 1
                    # subkeys are like "Package" or "NonPackaged" entries - read values
                    try:
                        with winreg.OpenKey(key, sub) as sk:
                            j = 0
                            while True:
                                try:
                                    val_name, val_data, _ = winreg.EnumValue(sk, j)
                                except OSError:
                                    break
                                j += 1
                                # val_data often JSON-like or strings; we check for 'Value' == 'Allow'
                                if isinstance(val_data, str) and "Allow" in val_data:
                                    caps[cap].append(sub)
                                elif isinstance(val_data, int) and val_data == 1:
                                    caps[cap].append(sub)
                    except Exception:
                        continue
        except FileNotFoundError:
            continue
        except PermissionError:
            continue
    return caps

# ---------------------------
# Network activity detection
# ---------------------------
def get_network_processes() -> Dict[int, Dict]:
    """
    Runs netstat -ano, finds PIDs with LISTENING/ESTABLISHED sockets.
    Maps PID -> {count_connections, sample_local_remote, process_name}
    Uses tasklist to map PID -> image name (non-admin).
    """
    procs = {}
    rc, out, err = safe_subprocess(["netstat", "-ano"])
    if rc != 0 or not out:
        return procs
    lines = out.splitlines()
    for line in lines:
        line = line.strip()
        parts = re.split(r"\s+", line)
        if len(parts) < 5:
            continue
        # typical: Proto LocalAddress ForeignAddress State PID
        proto = parts[0]
        pid = None
        try:
            pid = int(parts[-1])
        except Exception:
            continue
        state = parts[-2] if len(parts) >= 5 else ""
        if state.upper() in ("LISTENING", "ESTABLISHED", "SYN_SENT", "SYN_RECEIVED"):
            rec = procs.setdefault(pid, {"count": 0, "examples": set(), "proc_name": None})
            rec["count"] += 1
            # store a sample endpoint (local->remote)
            local = parts[1] if len(parts) > 1 else ""
            remote = parts[2] if len(parts) > 2 else ""
            rec["examples"].add(f"{local}->{remote} ({state})")
    # Map PIDs to process names via tasklist
    rc2, out2, err2 = safe_subprocess(["tasklist", "/FO", "CSV", "/NH"])
    if rc2 == 0 and out2:
        # parse CSV lines: "Image Name","PID","Session Name","Session#","Mem Usage"
        for line in out2.splitlines():
            try:
                cols = list(map(lambda s: s.strip('"'), line.split('","')))
                if len(cols) >= 2:
                    name = cols[0]
                    pid = int(cols[1])
                    if pid in procs:
                        procs[pid]["proc_name"] = name
            except Exception:
                continue
    # convert examples to list
    for pid, rec in procs.items():
        rec["examples"] = list(rec["examples"])[:3]
    return procs

# ---------------------------
# Authenticode signature check
# ---------------------------
def check_authenticode_signature(exe_path: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Use PowerShell Get-AuthenticodeSignature to check signature status.
    Returns (status, signer) or (None, None) if not available or fails.
    Status examples: 'Valid', 'NotSigned', 'UnknownError', 'HashMismatch'
    This is relatively fast for a few files; avoid running on every file to keep performance.
    """
    if not exe_path or not Path(exe_path).exists():
        return None, None
    # build PowerShell command: (Get-AuthenticodeSignature -FilePath 'C:\path\to.exe' | ConvertTo-Json -Compress)
    ps = f"Try{{(Get-AuthenticodeSignature -FilePath '{exe_path}' -ErrorAction Stop) | Select-Object Status,SignedBy | ConvertTo-Json -Compress}} Catch {{ Write-Output '' }}"
    rc, out, err = run_powershell(ps, timeout=6)
    if rc != 0 or not out:
        return None, None
    try:
        obj = json.loads(out)
        status = obj.get("Status")
        signer = obj.get("SignedBy")
        if signer:
            # signer could be object; convert to string
            if isinstance(signer, dict):
                signer = signer.get("FriendlyName") or str(signer)
        return status, signer
    except Exception:
        return None, None

# ---------------------------
# Scoring and reasoning
# ---------------------------
def compute_score_and_reason(entry: Dict,
                             network_map: Dict[int, Dict],
                             cam_consents: Dict[str, List[str]],
                             mic_consents: Dict[str, List[str]]) -> Dict:
    """
    Compute a numeric score and human-readable reason(s) for a program/startup entry.
    Scores:
      - admin_required: +3
      - restricted: +3
      - unknown publisher: +1
      - exe in unusual location: +2
      - camera consent for non-AV app: +3
      - microphone consent for non-AV app: +3
      - has network connections: +2
      - unsigned executable: +2
    Then map aggregate to LOW/MEDIUM/HIGH
    """
    score = 0
    reasons = []

    # admin
    if entry.get("admin_required"):
        score += 3
        reasons.append("Auto-runs with admin privileges")

    # restricted
    if entry.get("restricted"):
        score += 3
        reasons.append("Cannot inspect registry/details (restricted)")

    # publisher
    pub = entry.get("publisher") or ""
    if not pub or pub.strip() == "":
        score += 1
        reasons.append("Publisher unknown")

    # exe path / command checks
    cmd = entry.get("command") or ""
    exe = entry.get("exe_path") or ""
    path_flagged = False
    if exe:
        exe_l = exe.lower()
        if any(seg in exe_l for seg in ["\\temp\\", "\\downloads\\", "\\appdata\\", "\\local\\temp\\"]):
            score += 2
            reasons.append(f"Executable located in nonstandard location: {exe}")
            path_flagged = True
        # system paths are OK
        if exe_l.startswith(("c:\\windows\\", "c:\\program files\\" , "c:\\program files (x86)\\" )):
            # safe; no score change
            pass
    else:
        # try to infer exe from command string
        inferred = extract_exe_from_command(cmd)
        if inferred:
            entry["exe_path"] = inferred
            exe = inferred

    # background service indication
    if "service" in (cmd or "").lower() or "svc" in (cmd or "").lower():
        score += 1
        reasons.append("Appears to run as a background service")

    # startup/autostart
    src = entry.get("source") or ""
    if "Run" in src or "Startup" in src:
        # minor score for being persistent
        score += 1
        reasons.append(f"Persists via {src}")

    # network connections: check if any PID mapping matches this exe/name
    # network_map: pid -> {proc_name, count, examples}
    # We will attempt to match by proc_name or exe basename
    net_found = False
    try:
        for pid, rec in network_map.items():
            proc_name = (rec.get("proc_name") or "").lower()
            if not proc_name:
                continue
            # compare with entry name or exe basename
            if entry.get("name") and entry["name"].lower() in proc_name:
                net_found = True
            elif exe and Path(exe).name.lower() in proc_name:
                net_found = True
            if net_found:
                score += 2
                reasons.append(f"Active network connections (PID {pid}, sample: {rec.get('examples',[])[0] if rec.get('examples') else ''})")
                break
    except Exception:
        pass

    # camera / mic consents: if entry name or package matches consent lists
    # cam_consents and mic_consents keys are appids; we try simple substring match against entry name
    name_lower = (entry.get("name") or "").lower()
    cam_flag = False
    mic_flag = False
    try:
        for appid in cam_consents.get("webcam", []):
            if appid and appid.lower() in name_lower:
                cam_flag = True
        for appid in mic_consents.get("microphone", []):
            if appid and appid.lower() in name_lower:
                mic_flag = True
    except Exception:
        pass
    # If camera/mic access present AND entry is not obviously a camera/communication app, raise score
    camera_app_keywords = ["camera", "zoom", "obs", "webex", "teams", "skype", "viber"]
    if cam_flag:
        # if name doesn't look like a camera/meeting app
        if not any(k in name_lower for k in camera_app_keywords):
            score += 3
            reasons.append("Has camera access but not an obvious camera/meeting app")
    if mic_flag:
        if not any(k in name_lower for k in camera_app_keywords):
            score += 3
            reasons.append("Has microphone access but not an obvious audio app")

    # signature check (try if exe available)
    sig_status = None
    signer = None
    try:
        if exe and Path(exe).exists():
            sig_status, signer = check_authenticode_signature(exe)
            if sig_status and sig_status not in ("Valid",):
                score += 2
                reasons.append(f"Executable signature status: {sig_status}")
            elif sig_status == "Valid":
                # trusted, reduce weight of unknown publisher slightly
                if "Publisher unknown" in reasons:
                    # reduce by 1
                    score = max(0, score - 1)
                    reasons = [r for r in reasons if r != "Publisher unknown"]
                    reasons.append(f"Publisher verified by signature: {signer or 'unknown signer'}")
    except Exception:
        pass

    # Compose final risk
    # score ranges: 0-2 LOW, 3-5 MEDIUM, 6+ HIGH
    if score <= 2:
        risk = "LOW"
    elif score <= 5:
        risk = "MEDIUM"
    else:
        risk = "HIGH"

    entry_out = dict(entry)  # copy
    entry_out["score"] = score
    entry_out["risk"] = risk
    entry_out["reason"] = "; ".join(reasons) if reasons else "No concerning combined indicators"
    if sig_status:
        entry_out["signature_status"] = sig_status
    if signer:
        entry_out["signature_signer"] = signer
    return entry_out

# ---------------------------
# Top-risk ordering helper
# ---------------------------
def sort_top_risks(items: List[Dict]) -> List[Dict]:
    # Primary by risk (HIGH first), secondary by score desc, tertiary by restricted/ admin flags
    risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    def keyfn(x):
        return (risk_order.get(x.get("risk","LOW"), 2), -x.get("score", 0), -int(bool(x.get("restricted"))), -int(bool(x.get("admin_required"))))
    return sorted(items, key=keyfn)

# ---------------------------
# Main orchestrator & CLI
# ---------------------------
def run_permissions_audit(limit_output: int = 100):
    print("Full Permissions Audit (Windows) — lightweight, multi-metric analysis\n")

    # Step 1: enumerate programs & startups
    print("Scanning installed programs and startup items (registry + startup folders)...")
    programs = get_installed_programs()
    startups = get_startup_programs()

    # Step 2: capability consents
    print("Reading camera/microphone capability consents...")
    caps = get_capability_consents()
    # cams = caps['webcam'] ; mics = caps['microphone']
    cam_consents = {"webcam": caps.get("webcam", [])}
    mic_consents = {"microphone": caps.get("microphone", [])}

    # Step 3: network scan
    print("Detecting active network-connected processes (netstat -> tasklist)...")
    network_map = get_network_processes()

    # Step 4: assess each entry using multi-factor scoring
    print("Assessing risk for found items...")
    assessed_programs = []
    for p in programs:
        # enrich some fields for evaluation
        entry = {
            "type": "program",
            "name": p.get("name"),
            "publisher": p.get("publisher"),
            "version": p.get("version"),
            "install_location": p.get("install_location"),
            "command": p.get("displayicon") or p.get("exe_path"),
            "exe_path": p.get("exe_path"),
            "restricted": p.get("restricted", False),
            "source": p.get("source", "Registry")
        }
        assessed_programs.append(compute_score_and_reason(entry, network_map, cam_consents, mic_consents))

    assessed_startups = []
    for s in startups:
        entry = {
            "type": "startup",
            "name": s.get("name"),
            "command": s.get("command"),
            "exe_path": s.get("exe_path"),
            "restricted": s.get("restricted", False),
            "admin_required": s.get("admin_required", False),
            "source": s.get("source", "Startup")
        }
        assessed_startups.append(compute_score_and_reason(entry, network_map, cam_consents, mic_consents))

    # Step 5: output (color-coded)
    def fmt_risk_tag(risk_str: str) -> str:
        if not Fore:
            return risk_str
        if risk_str == "HIGH":
            return color("HIGH", Fore.RED)
        if risk_str == "MEDIUM":
            return color("MED", Fore.YELLOW)
        return color("LOW", Fore.GREEN)

    print("\n--- Programs (sample) ---")
    if not assessed_programs:
        print("  No installed programs found.")
    else:
        for item in assessed_programs[:limit_output]:
            tag = fmt_risk_tag(item["risk"])
            print(f"  - {item.get('name')} [{item.get('source')}] — {tag} — score={item.get('score')} — {item.get('reason')}")
            # optionally show exe path/signature
            if item.get("exe_path"):
                print(f"      path: {item.get('exe_path')}  sig: {item.get('signature_status', 'N/A')}")

    print("\n--- Startup items (sample) ---")
    if not assessed_startups:
        print("  No startup items found.")
    else:
        for item in assessed_startups[:limit_output]:
            tag = fmt_risk_tag(item["risk"])
            admin = "(admin)" if item.get("admin_required") else ""
            print(f"  - {item.get('name')} [{item.get('source')}] {admin} — {tag} — score={item.get('score')} — {item.get('reason')}")
            if item.get("exe_path"):
                print(f"      path: {item.get('exe_path')}  sig: {item.get('signature_status', 'N/A')}")

    # Step 6: top-risk summary
    combined = assessed_programs + assessed_startups
    top = sort_top_risks([c for c in combined if c.get("risk") in ("HIGH", "MEDIUM")])[:8]
    print("\n=== TOP RISKS (review first) ===")
    if not top:
        print("  No medium/high risk items detected.")
    else:
        for t in top:
            tag = fmt_risk_tag(t["risk"])
            src = t.get("source", "Program/Startup")
            admin = " (admin)" if t.get("admin_required") else ""
            print(f"  - {t.get('name')} [{src}]{admin} — {tag} — score={t.get('score')}")
            print(f"      Reason: {t.get('reason')}")
            if t.get("exe_path"):
                print(f"      Path: {t.get('exe_path')}")
            if t.get("signature_status"):
                print(f"      Signature: {t.get('signature_status')} / {t.get('signature_signer','-')}")
            # if network info present, show short sample
            # attempt to find network rec for matching proc_name or exe basename
            for pid, netrec in network_map.items():
                pn = (netrec.get("proc_name") or "").lower()
                if (t.get("name") and t["name"].lower() in pn) or (t.get("exe_path") and Path(t["exe_path"]).name.lower() in pn):
                    print(f"      Network: PID {pid}, connections: {netrec.get('count')} sample: {netrec.get('examples')[:1]}")
                    break

    print("\nScan complete. Review 'TOP RISKS' and address items you don't recognize or that have concerning reasons.")
    print("Note: This tool is a lightweight, static/metadata-driven scanner. For dynamic analysis or removal, use dedicated endpoint/AV tools.")
    return {
            "top_risks": top,
            "all_programs": assessed_programs,
            "all_startups": assessed_startups,
            "summary": {
                "total_programs": len(assessed_programs),
                "total_startups": len(assessed_startups),
                "high_risk_count": len([x for x in combined if x.get("risk") == "HIGH"]),
                "medium_risk_count": len([x for x in combined if x.get("risk") == "MEDIUM"]),
                "low_risk_count": len([x for x in combined if x.get("risk") == "LOW"])
            }
        }
# ---------------------------
# CLI
# ---------------------------
if __name__ == "__main__":
    run_permissions_audit()
