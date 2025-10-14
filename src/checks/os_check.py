import platform
import ctypes
import subprocess
import datetime

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


def check_defender_status():
    """
    Checks Windows Defender real-time protection and signature status.
    Returns:
        dict: {
            "defender_enabled": True/False/None,  # None if cannot check
            "signature_version": str or None,
            "definition_age_days": int or None,
            "risk_flag": str,  # "Low", "Medium", "High"
            "message": str
        }
    """
    result_dict = {
        "defender_enabled": None,
        "signature_version": None,
        "definition_age_days": None,
        "risk_flag": "Unknown",
        "message": ""
    }

    try:
        # ===== Real-time protection =====
        cmd_realtime = [
            "powershell",
            "-Command",
            "Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled"
        ]
        rt_result = subprocess.run(cmd_realtime, capture_output=True, text=True)
        rt_output = rt_result.stdout.strip().lower()

        if rt_output == "true":
            result_dict["defender_enabled"] = True
        elif rt_output == "false":
            result_dict["defender_enabled"] = False
        else:
            result_dict["defender_enabled"] = None

        # ===== Signature version & last update =====
        cmd_sig = [
            "powershell",
            "-Command",
            "Get-MpComputerStatus | "
            "Select-Object -ExpandProperty AntivirusSignatureLastUpdated"
        ]
        sig_result = subprocess.run(cmd_sig, capture_output=True, text=True)
        sig_output = sig_result.stdout.strip()

        if sig_output:
            result_dict["signature_version"] = sig_output

            # Convert to datetime to compute age
            try:
                last_update = datetime.datetime.strptime(sig_output, "%m/%d/%Y %I:%M:%S %p")
                age_days = (datetime.datetime.now() - last_update).days
                result_dict["definition_age_days"] = age_days
            except:
                result_dict["definition_age_days"] = None

        # ===== Risk evaluation =====
        if result_dict["defender_enabled"] is False or \
           (result_dict["definition_age_days"] is not None and result_dict["definition_age_days"] > 7):
            result_dict["risk_flag"] = "High"
            result_dict["message"] = "Defender is off or virus definitions are outdated. Update immediately."
        elif result_dict["defender_enabled"] is True:
            result_dict["risk_flag"] = "Low"
            result_dict["message"] = "Defender is active and virus definitions are reasonably up to date."
        else:
            result_dict["risk_flag"] = "Medium"
            result_dict["message"] = "Unable to reliably determine Defender status. Run as admin."

    except Exception as e:
        result_dict["risk_flag"] = "Unknown"
        result_dict["message"] = f"Error checking Defender status: {str(e)}"

    return result_dict


# ======= Test Run =======
if __name__ == "__main__":
    status = check_defender_status()
    for k, v in status.items():
        print(f"{k}: {v}")