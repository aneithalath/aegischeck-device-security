import platform
import ctypes
import subprocess

def get_os_info():
    """
    Retrieves the operating system information.
    
    Returns:
        dict: A dictionary containing the OS name, version, and release.
    """
    system = platform.system()
    version = platform.version()
    release = platform.release()

    # Default build number parsing
    try:
        build_number = version.split('.')[-1]  # e.g., '19044'
    except:
        build_number = version

    # Detect edition using systeminfo (Windows only)
    edition = "Unknown"
    if system == "Windows":
        try:
            result = subprocess.run(
                ["systeminfo"],
                capture_output=True,
                text=True
            )
            for line in result.stdout.splitlines():
                if "OS Name" in line:
                    # e.g., 'OS Name:                   Microsoft Windows 10 Pro'
                    edition = line.split("Windows")[-1].strip()
        except:
            edition = "Unknown"

    # Hard-coded latest builds for MVP (these are not the latest right now)
    latest_builds = {"10": 19045, "11": 22621}  # 19045 = latest Win10, 22621 = latest Win11
    status = "Up to date"

    # Compare build number
    try:
        if system == "Windows" and release in latest_builds:
            if int(build_number) < latest_builds[release]:
                status = "Outdated"
    except:
        status = "Unknown"

    return {
        "os": system,
        "version": release,
        "build": build_number,
        "edition": edition,
        "status": status
    }

def check_firewall_status():
    """
    Checks Windows Firewall status for all profiles (Domain, Private, Public).
    Returns:
        dict: {
            "firewall_enabled": True/False,  # True if all profiles are ON
            "profiles": {"Domain": True/False, "Private": True/False, "Public": True/False}
        }
    """
    def parse_firewall_output(output):
        profiles = {}
        current_profile = None
        for line in output.splitlines():
            line = line.strip()
            if "Profile Settings:" in line:
                current_profile = line.split("Profile")[0].strip()  # Domain / Private / Public
            elif line.lower().startswith("state") and current_profile:
                status = "on" in line.lower()
                profiles[current_profile] = status
        return profiles

    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles", "state"],
            capture_output=True,
            text=True
        )
        profiles_status = parse_firewall_output(result.stdout)
        overall = all(profiles_status.values()) if profiles_status else None
        return {"firewall_enabled": overall, "profiles": profiles_status}

    except Exception as e:
        return {"firewall_enabled": None, "error": str(e)}


# ======= Test Run =======
if __name__ == "__main__":
    firewall_status = check_firewall_status()
    print(firewall_status)