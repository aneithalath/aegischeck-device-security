# src/hibp_helper.py
"""
HIBP helper: k-anonymity lookup + local prefix cache.

Provides:
- sha1_hex(password) -> 40-char uppercase SHA1 hex
- hibp_check_hash(sha1_hex_str, cache=None) -> int breach_count or 0 if not found, or None on network error

Cache file: ./data/hibp_cache.json (created automatically)
"""

import hashlib
import requests
import json
import time
from pathlib import Path
from typing import Optional, Dict, List

# -----------------------
# Config / constants
# -----------------------
PROJECT_ROOT = Path.cwd()
CACHE_DIR = PROJECT_ROOT / "data"
CACHE_PATH = CACHE_DIR / "hibp_cache.json"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# ensure cache file exists
if not CACHE_PATH.exists():
    CACHE_PATH.write_text(json.dumps({}))

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{}"
HEADERS = {"User-Agent": "PersonalDeviceSecurityChecker/1.0"}  # be polite and identifiable

# -----------------------
# Cache helpers
# -----------------------
def load_cache() -> Dict[str, List[str]]:
    """Load prefix->lines cache from disk. Returns empty dict on error."""
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            # ensure keys are upper-case prefixes for consistent lookup
            return {k.upper(): v for k, v in data.items()}
    except Exception:
        return {}

def save_cache(cache: Dict[str, List[str]]) -> None:
    """Persist cache to disk (best-effort)."""
    try:
        # convert keys to upper-case strings (JSON keys must be str)
        serializable = {str(k).upper(): v for k, v in cache.items()}
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=2)
    except Exception:
        # don't crash the caller if saving fails
        pass

# -----------------------
# Utility helpers
# -----------------------
def sha1_hex(password: str) -> str:
    """Return uppercase SHA-1 hex string for the given password."""
    if password is None:
        raise ValueError("password must be a string")
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

def parse_range_response(text: str) -> List[str]:
    """
    Parse the plain-text response from HIBP /range endpoint into a list of lines.
    Each line is like: 'A1B2C3...:123'
    """
    return [line.strip() for line in text.splitlines() if line.strip()]

# -----------------------
# Main function
# -----------------------
def hibp_check_hash(sha1_hex_str: str, cache: Optional[Dict[str, List[str]]] = None, max_retries: int = 2) -> Optional[int]:
    """
    Check a full SHA1 hex (40 chars, uppercase) against HIBP using k-anonymity.
    - sha1_hex_str: full SHA1 hex string (uppercase)
    - cache: optional in-memory cache (prefix -> list of 'suffix:count' lines). If None, will load from disk.
    - max_retries: how many times to retry network calls on transient failure.

    Returns:
      - int breach_count (>=0) if successful,
      - 0 if not found,
      - None if network/API error occurred.
    Side effects:
      - may update cache dict (in-memory). Caller should call save_cache(cache) if they want to persist.
    """
    if not sha1_hex_str or len(sha1_hex_str) != 40:
        raise ValueError("sha1_hex_str must be a 40-character SHA1 hex string (uppercase).")

    if cache is None:
        cache = load_cache()

    prefix = sha1_hex_str[:5].upper()
    suffix = sha1_hex_str[5:].upper()

    # If cached, use it
    if prefix in cache:
        lines = cache[prefix]
    else:
        # fetch from HIBP with retries/backoff
        url = HIBP_RANGE_URL.format(prefix)
        attempt = 0
        lines = None
        while attempt <= max_retries:
            try:
                resp = requests.get(url, headers=HEADERS, timeout=10)
                if resp.status_code == 200:
                    lines = parse_range_response(resp.text)
                    cache[prefix] = lines
                    # try to persist cache, but don't blow up if it fails
                    try:
                        save_cache(cache)
                    except Exception:
                        pass
                    break
                else:
                    # unexpected status: treat as transient and retry with backoff
                    attempt += 1
                    time.sleep(1.5 * attempt)
            except requests.RequestException:
                attempt += 1
                time.sleep(1.5 * attempt)
        if lines is None:
            return None  # network/API failure

    # search for suffix
    for line in cache.get(prefix, []):
        parts = line.split(":")
        if len(parts) >= 2 and parts[0].strip().upper() == suffix:
            try:
                return int(parts[1].strip())
            except Exception:
                return 1
    return 0

# -----------------------
# Lightweight CLI test
# -----------------------
if __name__ == "__main__":
    print("HIBP helper quick test (k-anonymity).")
    pw = input("Enter a password to test (or press Enter to test 'password'):\n").strip()
    if not pw:
        pw = "password"
    sha = sha1_hex(pw)
    print("Computed SHA1 (first 10 chars):", sha[:10], "...")
    cache = load_cache()
    count = hibp_check_hash(sha, cache=cache)
    if count is None:
        print("HIBP lookup failed (network/API).")
    elif count == 0:
        print("Password NOT found in HIBP — good (risk: Low).")
    else:
        level = "High" if count > 100 else ("Medium" if count > 0 else "Low")
        print(f"Password FOUND {count} times in breaches. Risk: {level}")
