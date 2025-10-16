# src/hibp_k_anonymity_test.py
import hashlib
import requests

HEADERS = {"User-Agent": "PersonalDeviceSecurityChecker/1.0"}
HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{}"

def sha1_hex(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

def check_password_with_hibp(password: str):
    sha = sha1_hex(password)
    prefix, suffix = sha[:5], sha[5:]
    print(f"SHA1: {sha}")
    print(f"Prefix: {prefix}  Suffix: {suffix[:8]}...")

    r = requests.get(HIBP_RANGE_URL.format(prefix), headers=HEADERS, timeout=10)
    if r.status_code != 200:
        print("HIBP request failed:", r.status_code)
        return None

    for line in r.text.splitlines():
        parts = line.split(":")
        if parts[0].strip().upper() == suffix:
            try:
                count = int(parts[1].strip())
            except:
                count = 1
            return count
    return 0

if __name__ == "__main__":
    pw = input("Enter a password to test (or press Enter to test 'password'):\n").strip()
    if not pw:
        pw = "password"
    count = check_password_with_hibp(pw)
    if count is None:
        print("Could not check HIBP (network/API error).")
    elif count == 0:
        print("Password NOT found in HIBP — good (risk: Low).")
    else:
        level = "High" if count > 100 else ("Medium" if count > 0 else "Low")
        print(f"Password FOUND {count} times in breaches. Risk: {level}")
