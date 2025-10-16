import platform
import ctypes
import subprocess
import datetime
import sys
import os

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

    # Hard-coded latest builds for MVP
    latest_builds = {"10": 19045, "11": 26200}  # 19045 = latest Win10, 26200 = latest Win11
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


def check_admin_privileges():
    """
    Checks for admin privileges and UAC status on Windows.
    Returns:
        dict: {
            "running_as_admin": True/False,
            "uac_enabled": True/False/None,
            "message": str
        }
    """
    status = {
        "running_as_admin": False,
        "uac_enabled": None,
        "message": ""
    }

    try:
        # ===== Check if script is running as admin =====
        status["running_as_admin"] = ctypes.windll.shell32.IsUserAnAdmin() != 0

        # ===== Check if UAC is enabled =====
        try:
            uac_check_cmd = [
                "powershell",
                "-Command",
                "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').EnableLUA"
            ]
            uac_result = subprocess.run(uac_check_cmd, capture_output=True, text=True)
            uac_value = uac_result.stdout.strip()
            if uac_value == "1":
                status["uac_enabled"] = True
            elif uac_value == "0":
                status["uac_enabled"] = False
            else:
                status["uac_enabled"] = None
        except:
            status["uac_enabled"] = None

        # ===== Generate message =====
        if status["running_as_admin"]:
            status["message"] = "Script is running as admin."
            if status["uac_enabled"] is False:
                status["message"] += " Warning: UAC is disabled — system is more vulnerable."
        else:
            status["message"] = "Script is not running as admin. Some checks may be limited."

    except Exception as e:
        status["message"] = f"Error checking admin privileges: {str(e)}"

    return status

def run_as_admin():
    """
    Relaunches the current script with admin privileges on Windows.
    Returns True if already admin, False if failed/elevating.
    """
    if ctypes.windll.shell32.IsUserAnAdmin():
        # Already running as admin
        return True

    try:
        # Full path to python interpreter
        python_exe = sys.executable
        # Full path to this script
        script = os.path.abspath(sys.argv[0])
        # Build parameters string
        params = f'"{script}" {" ".join(sys.argv[1:])}'
        # Run as admin
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", python_exe, params, None, 1)
        if ret <= 32:
            # Any return <=32 is a failure
            return False
        else:
            # Successfully launched elevated; original process should exit
            return False
    except Exception as e:
        print(f"Failed to elevate privileges: {e}")
        return False
    
from colorama import init, Fore, Style
init(autoreset=True)

def print_risk(label, risk_level):
    """Print a label with color-coded risk level."""
    color = {"Low": Fore.GREEN, "Medium": Fore.YELLOW, "High": Fore.RED}.get(risk_level, Fore.WHITE)
    print(f"{label}: {color}{risk_level}{Style.RESET_ALL}")

def evaluate_os_security():
    """
    Aggregates Windows security checks and outputs a CLI report.
    Returns:
        dict: Structured report including per-check results, overall risk, and recommendations.
    """
    report = {
        "os_info": {},
        "firewall_status": {},
        "defender_status": {},
        "admin_status": {},
        "overall_risk": "Unknown",
        "recommendations": []
    }

    # ===== 1. Admin check =====
    admin_status = check_admin_privileges()
    report["admin_status"] = admin_status

    if not admin_status["running_as_admin"]:
        choice = input("\nSome checks require admin privileges. Restart script as admin? (Y/N): ").strip().lower()
        if choice == "y":
            if run_as_admin():
                sys.exit()  # Already admin, new process continues
            else:
                print("Failed to elevate. Continuing with limited checks.")

    # ===== 2. OS info =====
    os_info = get_os_info()
    report["os_info"] = os_info

    # Evaluate OS version/build risk
    os_risk = "Low"
    if os_info["status"] == "Outdated":
        os_risk = "Medium"
        report["recommendations"].append(f"Update Windows {os_info['version']} build {os_info['build']} to the latest version.")
    
    # ===== 3. Firewall =====
    fw_status = check_firewall_status()
    report["firewall_status"] = fw_status

    fw_risk = "Low"
    if not fw_status["firewall_enabled"]:
        fw_risk = "High"
        for profile, enabled in fw_status["profiles"].items():
            if not enabled:
                report["recommendations"].append(f"Enable firewall for {profile} profile.")

    # ===== 4. Defender =====
    defender_status = check_defender_status()
    report["defender_status"] = defender_status

    defender_risk = defender_status["risk_flag"]

    if defender_status["risk_flag"] in ["Medium", "High"]:
        report["recommendations"].append(defender_status["message"])

    # ===== 5. Aggregate overall risk =====
    risk_levels = [os_risk, fw_risk, defender_risk]
    if "High" in risk_levels:
        report["overall_risk"] = "High"
    elif "Medium" in risk_levels:
        report["overall_risk"] = "Medium"
    else:
        report["overall_risk"] = "Low"

    # ===== 6. CLI Output =====
    print("\n=== WINDOWS OS SECURITY REPORT ===\n")

    # OS info
    print("OS Info:")
    print(f"  Name: {os_info['os']}")
    print(f"  Version: {os_info['version']}")
    print(f"  Build: {os_info['build']}")
    print(f"  Edition: {os_info['edition']}")
    print_risk("OS Risk", os_risk)
    print()

    # Firewall
    print("Firewall Status:")
    for profile, enabled in fw_status["profiles"].items():
        status_str = "Enabled" if enabled else "Disabled"
        risk = "Low" if enabled else "High"
        print(f"  {profile}: {status_str}")
        print_risk(f"  {profile} Risk", risk)
    print_risk("Firewall Overall Risk", fw_risk)
    print()

    # Defender
    print("Windows Defender:")
    defender_enabled = "Enabled" if defender_status["defender_enabled"] else "Disabled"
    print(f"  Real-time Protection: {defender_enabled}")
    sig_age = defender_status["definition_age_days"]
    if sig_age is not None:
        print(f"  Definitions Age: {sig_age} days")
    print_risk("Defender Risk", defender_risk)
    print()

    # Admin/UAC
    print("Admin Privileges:")
    running = "Yes" if admin_status["running_as_admin"] else "No"
    print(f"  Running as Admin: {running}")
    uac = admin_status["uac_enabled"]
    uac_str = "Enabled" if uac else ("Disabled" if uac is False else "Unknown")
    print(f"  UAC: {uac_str}")
    print_risk("Admin Risk", "Medium" if not admin_status["running_as_admin"] else "Low")
    print()

    # Overall
    print_risk("OVERALL SYSTEM RISK", report["overall_risk"])
    print("\nRecommended Actions:")
    if report["recommendations"]:
        for rec in report["recommendations"]:
            print(f"  - {rec}")
    else:
        print("  None, your system looks secure!")

    return report

# ======= Test Run =======
if __name__ == "__main__":
    evaluate_os_security()