import requests

HEADERS = {"User-Agent": "PersonalDeviceSecurityChecker/1.0"}
url = "https://api.pwnedpasswords.com/range/5BAA6"
r = requests.get(url, headers=HEADERS, timeout=10)
print("status:", r.status_code)

if r.status_code == 200:
    lines = r.text.splitlines()
    print("first 10 lines:")
    for i, line in enumerate(lines[:10]):
        print(i + 1, line)
else:
    print("response text:", r.text[:400])
