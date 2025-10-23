import platform

"""
OS Security Check Module
-----------------------
Checks for OS patch level, update status, and basic security settings.
"""
import platform
import datetime
import subprocess
from typing import Dict, Any

# Optional color output
try:
    from colorama import Fore, Style
    COLOR_ENABLED = True
except ImportError:
    COLOR_ENABLED = False
    class DummyFore:
        def __getattr__(self, name): return ""
    class DummyStyle:
        def __getattr__(self, name): return ""
    Fore = DummyFore()
    Style = DummyStyle()

def evaluate_os_security() -> Dict[str, Any]:
    """
    Evaluate OS security status and return structured results.
    """
    result = {
        'overall_risk': 'Unknown',
        'details': {}
    }
    system = platform.system()
    release = platform.release()
    version = platform.version()
    now = datetime.datetime.now()
    result['details']['system'] = system
    result['details']['release'] = release
    result['details']['version'] = version
    result['details']['scan_time'] = now.isoformat()

    # Patch level (Windows only)
    patch_level = 'Unknown'
    recent_update = 'Unknown'
    if system == 'Windows':
        try:
            # Get last update date
            cmd = ['wmic', 'qfe', 'get', 'InstalledOn']
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            dates = [line.strip() for line in proc.stdout.splitlines() if line.strip() and line.strip() != 'InstalledOn']
            if dates:
                recent_update = max(dates)
                result['details']['recent_update'] = recent_update
                # Simple patch level heuristic
                patch_level = recent_update
        except Exception:
            pass
    result['details']['patch_level'] = patch_level

    # Risk logic
    if system == 'Windows':
        if patch_level == 'Unknown' or recent_update == 'Unknown':
            result['overall_risk'] = 'Critical'
        else:
            # If last update > 90 days ago, high risk
            try:
                dt = datetime.datetime.strptime(recent_update, '%m/%d/%Y')
                days_since = (now - dt).days
                if days_since > 180:
                    result['overall_risk'] = 'Critical'
                elif days_since > 90:
                    result['overall_risk'] = 'High'
                elif days_since > 30:
                    result['overall_risk'] = 'Medium'
                else:
                    result['overall_risk'] = 'Low'
            except Exception:
                result['overall_risk'] = 'Unknown'
    else:
        result['overall_risk'] = 'Low'  # Default for non-Windows

        return result
    
def parse_firewall_output(output):
    """
    Parse netsh advfirewall output into a dict of profile -> enabled (bool).
    """
    profiles = {}
    current_profile = None
    for line in output.splitlines():
        raw = line.strip()
        if not raw:
            continue
        # Detect lines like "Domain Profile Settings" or "Private Profile"
        if raw.lower().endswith("profile settings") or raw.lower().endswith("profile"):
            # Use the first token as the profile name (Domain, Private, Public, All)
            current_profile = raw.split()[0].capitalize()
            continue
        # Lines containing state usually indicate ON/OFF
        if "state" in raw.lower():
            status = "on" in raw.lower()
            if current_profile is None:
                current_profile = "All"
            profiles[current_profile] = status
    return profiles

def check_fw_status():
    """
    Checks Windows Firewall status for all profiles using netsh.
    """
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
    """
    result_dict = {
        "defender_enabled": None,
        "signature_version": None,
        "definition_age_days": None,
        "risk_flag": "Unknown",
        "message": ""
    }

    try:
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
            try:
                last_update = datetime.datetime.strptime(sig_output, "%m/%d/%Y %I:%M:%S %p")
                age_days = (datetime.datetime.now() - last_update).days
                result_dict["definition_age_days"] = age_days
            except:
                result_dict["definition_age_days"] = None

        if result_dict["defender_enabled"] is False or \
           (result_dict["definition_age_days"] and result_dict["definition_age_days"] > 7):
            result_dict["risk_flag"] = "High"
            result_dict["message"] = "Defender is off or definitions are outdated."
        elif result_dict["defender_enabled"] is True:
            result_dict["risk_flag"] = "Low"
            result_dict["message"] = "Defender is active and up to date."
        else:
            result_dict["risk_flag"] = "Medium"
            result_dict["message"] = "Unable to determine Defender status."
    except Exception as e:
        result_dict["risk_flag"] = "Unknown"
        result_dict["message"] = f"Error checking Defender: {str(e)}"

    return result_dict


def check_admin_privileges():
    """
    Reports admin and UAC status but doesn’t elevate or prompt.
    """
    import ctypes
    status = {"running_as_admin": False, "uac_enabled": None, "message": ""}

    try:
        status["running_as_admin"] = ctypes.windll.shell32.IsUserAnAdmin() != 0

        try:
            cmd = [
                "powershell",
                "-Command",
                "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').EnableLUA"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            uac_value = result.stdout.strip()
            if uac_value == "1":
                status["uac_enabled"] = True
            elif uac_value == "0":
                status["uac_enabled"] = False
        except:
            status["uac_enabled"] = None

        if status["uac_enabled"] is False:
            status["message"] = "Warning: UAC is disabled — your system is more vulnerable."
        elif not status["running_as_admin"]:
            status["message"] = "Running without admin privileges (normal mode)."
        else:
            status["message"] = "Running as admin."
    except Exception as e:
        status["message"] = f"Error checking admin privileges: {str(e)}"

    return status


def print_risk(label, risk_level):
    color = {"Low": Fore.GREEN, "Medium": Fore.YELLOW, "High": Fore.RED}.get(risk_level, Fore.WHITE)
    print(f"{label}: {color}{risk_level}{Style.RESET_ALL}")


def get_os_info():
    """
    Collect basic OS information used by the report.
    Returns a dict with keys: os, version, build, edition, status
    """
    info = {
        "os": platform.system(),
        "version": platform.version(),
        "build": platform.release(),
        "edition": "Unknown",
        "status": "Unknown"
    }
    try:
        if info["os"] == "Windows":
            # Attempt to get richer info via PowerShell (best-effort; non-fatal)
            cmd = [
                "powershell",
                "-Command",
                "Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Version,BuildNumber,Caption | ConvertTo-Json -Compress"
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if proc.stdout:
                try:
                    import json
                    data = json.loads(proc.stdout)
                    info["version"] = data.get("Version", info["version"])
                    info["build"] = data.get("BuildNumber", info["build"])
                    info["edition"] = data.get("Caption", info["edition"])
                except Exception:
                    # Keep best-effort values if parsing fails
                    pass
            # Simple heuristic: mark as Up to date by default (detailed checks would inspect update dates)
            info["status"] = "Up to date"
        else:
            info["status"] = "Up to date"
    except Exception:
        info["status"] = "Unknown"
    return info

def evaluate_os_security():
    """
    Runs all OS-level checks (no admin required).
    """
    report = {
        "os_info": {},
        "firewall_status": {},
        "defender_status": {},
        "admin_status": {},
        "overall_risk": "Unknown",
        "recommendations": []
    }

    admin_status = check_admin_privileges()
    report["admin_status"] = admin_status

    os_info = get_os_info()
    report["os_info"] = os_info

    os_risk = "Low" if os_info["status"] == "Up to date" else "Medium"
    if os_info["status"] == "Outdated":
        report["recommendations"].append(f"Update Windows {os_info['version']} build {os_info['build']}.")

    fw_status = check_fw_status()
    report["firewall_status"] = fw_status
    fw_risk = "Low" if fw_status["firewall_enabled"] else "High"
    if not fw_status["firewall_enabled"]:
        report["recommendations"].append("Enable Windows Firewall for all profiles.")

    defender_status = check_defender_status()
    report["defender_status"] = defender_status
    defender_risk = defender_status["risk_flag"]
    if defender_status["risk_flag"] in ["Medium", "High"]:
        report["recommendations"].append(defender_status["message"])

    risk_levels = [os_risk, fw_risk, defender_risk]
    if "High" in risk_levels:
        report["overall_risk"] = "High"
    elif "Medium" in risk_levels:
        report["overall_risk"] = "Medium"
    else:
        report["overall_risk"] = "Low"

    # ===== CLI Output =====
    print("\n=== WINDOWS OS SECURITY REPORT ===\n")

    print("OS Info:")
    print(f"  Name: {os_info['os']}")
    print(f"  Version: {os_info['version']}")
    print(f"  Build: {os_info['build']}")
    print(f"  Edition: {os_info['edition']}")
    print_risk("OS Risk", os_risk)
    print()

    print("Firewall Status:")
    for profile, enabled in fw_status.get("profiles", {}).items():
        print(f"  {profile}: {'Enabled' if enabled else 'Disabled'}")
    print_risk("Firewall Risk", fw_risk)
    print()

    print("Windows Defender:")
    print(f"  Real-time Protection: {'Enabled' if defender_status['defender_enabled'] else 'Disabled'}")
    if defender_status["definition_age_days"] is not None:
        print(f"  Definitions Age: {defender_status['definition_age_days']} days")
    print_risk("Defender Risk", defender_risk)
    print()

    print("Admin Privileges:")
    print(f"  Running as Admin: {'Yes' if admin_status['running_as_admin'] else 'No'}")
    uac_str = "Enabled" if admin_status['uac_enabled'] else ("Disabled" if admin_status['uac_enabled'] is False else "Unknown")
    print(f"  UAC: {uac_str}")
    print(admin_status["message"])
    print_risk("Admin Risk", "Low" if admin_status["uac_enabled"] else "Medium")
    print()

    print_risk("OVERALL SYSTEM RISK", report["overall_risk"])
    print("\nRecommendations:")
    if report["recommendations"]:
        for rec in report["recommendations"]:
            print(f"  - {rec}")
    else:
        print("  None, your system looks secure!")

    return report


if __name__ == "__main__":
    evaluate_os_security()
