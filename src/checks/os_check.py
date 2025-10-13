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


# ======= Test Run =======
if __name__ == "__main__":
    info = get_os_info()
    for key, value in info.items():
        print(f"{key}: {value}")
