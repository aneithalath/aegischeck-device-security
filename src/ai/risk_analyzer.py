
"""
Unified AI Risk Analyzer for Personal Device Security Advisor
------------------------------------------------------------
Analyzes outputs from OS, password, and permissions checks to generate a risk score and actionable recommendations.
Includes both Gemini (primary) and LocalRiskAnalyzer (fallback) logic. Operates fully locally if needed.
"""
import hashlib
from typing import Dict, Any, List

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

def colorize(text, risk):
    if not COLOR_ENABLED: return text
    if risk == "Critical": return f"{Fore.RED}{Style.BRIGHT}{text}{Style.RESET_ALL}"
    if risk == "High": return f"{Fore.RED}{text}{Style.RESET_ALL}"
    if risk == "Medium": return f"{Fore.YELLOW}{text}{Style.RESET_ALL}"
    if risk == "Low": return f"{Fore.GREEN}{text}{Style.RESET_ALL}"
    return text

def analyze_risks(os_results: Dict[str, Any], pw_results: Dict[str, Any], perm_results: Dict[str, Any], fallback: bool = False) -> Dict[str, Any]:
    """
    Analyze all check results and return a structured risk assessment.
    If fallback=True, use the local analyzer logic (no external APIs).
    Returns: {
        'score': float,
        'grade': str,
        'insights': List[str],
        'recommendations': List[str],
        'color': str,
        'health': str,
        'display': str
    }
    """
    if not fallback:
        # --- Gemini/Primary Analyzer Logic (local for now) ---
        insights = []
        recommendations = []
        score = 0.0
        grade = "Low"
        color = "Low"
        health = "OK"

        # --- OS Risk Trends ---
        os_risk = os_results.get('overall_risk', 'Unknown')
        os_details = os_results.get('details', {})
        patch_level = os_details.get('patch_level', 'Unknown')
        recent_update = os_details.get('recent_update', 'Unknown')
        if os_risk == "Critical":
            score += 2.5
            grade = "Critical"
            color = "Critical"
            insights.append("OS is critically outdated or misconfigured.")
            recommendations.append("Update your OS and review security settings immediately.")
        elif os_risk == "High":
            score += 2.0
            grade = "High"
            color = "High"
            insights.append("OS has high-risk vulnerabilities or missing patches.")
            recommendations.append("Install all pending updates and enable automatic patching.")
        elif os_risk == "Medium":
            score += 1.0
            grade = "Medium"
            color = "Medium"
            insights.append("OS is moderately secure but could be improved.")
            recommendations.append("Check for updates and review security settings.")
        elif os_risk == "Low":
            score += 0.5
            grade = "Low"
            color = "Low"
            insights.append("OS is up-to-date and well configured.")

        # --- Password Risk Profiling ---
        pw_summary = pw_results.get('summary', {})
        total_pw = pw_summary.get('total', 0)
        compromised_pw = pw_summary.get('compromised', 0)
        top_pw = pw_results.get('top_compromised', [])
        weak_pw_count = 0
        for entry in top_pw:
            breach_count = entry.get('breach_count', 0)
            if breach_count > 0:
                weak_pw_count += 1
        if compromised_pw > 0:
            score += min(2.0, compromised_pw * 0.3)
            insights.append(f"{compromised_pw} of {total_pw} saved passwords are compromised.")
            recommendations.append("Change all compromised passwords, especially those reused across sites.")
        elif total_pw > 0:
            insights.append("No compromised passwords detected.")
        else:
            insights.append("No saved passwords found.")
        if weak_pw_count > 0:
            recommendations.append(f"{weak_pw_count} passwords are weak or frequently breached. Use a password manager.")

        # --- Permissions & Auto-launch Correlation ---
        top_perm = perm_results.get('top_risks', [])
        risky_startup = [r for r in top_perm if r.get('risk', '') in ('High', 'Critical')]
        if risky_startup:
            score += len(risky_startup) * 0.5
            insights.append(f"{len(risky_startup)} risky startup programs or permissions detected.")
            recommendations.append("Review and disable unnecessary startup programs and permissions.")
        else:
            insights.append("No risky startup programs detected.")

        # --- Cross-layer Insights ---
        if os_risk in ("High", "Critical") and compromised_pw > 0 and risky_startup:
            score += 1.5
            insights.append("Pattern detected: Outdated OS, compromised passwords, and risky startup apps. Possible compromise.")
            recommendations.append("Perform a full malware scan and review all accounts and startup programs.")
        elif weak_pw_count > 0 and risky_startup:
            score += 1.0
            insights.append("Weak passwords combined with risky startup programs increase compromise risk.")
            recommendations.append("Change weak passwords and review startup programs.")
        elif os_risk in ("High", "Critical") and weak_pw_count > 0:
            score += 0.5
            insights.append("Outdated OS and weak passwords detected.")
            recommendations.append("Update OS and strengthen passwords.")

        # --- Final Scoring & Grade ---
        if score >= 5.0:
            grade = "Critical"
            color = "Critical"
        elif score >= 3.5:
            grade = "High"
            color = "High"
        elif score >= 2.0:
            grade = "Medium"
            color = "Medium"
        else:
            grade = "Low"
            color = "Low"

        return {
            'score': round(score, 2),
            'grade': grade,
            'color': color,
            'health': health,
            'insights': insights,
            'recommendations': recommendations,
            'display': colorize(f"Risk Grade: {grade} (Score: {score:.2f})", color)
        }
    else:
        # --- LocalRiskAnalyzer Fallback Logic ---
        insights: List[str] = []
        recommendations: List[str] = []
        score = 0
        grade = "Low"
        health = "FALLBACK MODE"

        # --- OS Check ---
        os_risk = os_results.get('overall_risk', 'Unknown')
        if os_risk == "Critical":
            score += 40
            grade = "Critical"
            insights.append("Critical OS issues detected.")
            recommendations.append("Update your OS and review security settings immediately.")
        elif os_risk == "High":
            score += 30
            grade = "High"
            insights.append("High-risk OS vulnerabilities or missing patches.")
            recommendations.append("Install all pending updates and enable automatic patching.")
        elif os_risk == "Medium":
            score += 15
            grade = "Medium"
            insights.append("Moderate OS security. Improvements recommended.")
            recommendations.append("Check for updates and review security settings.")
        elif os_risk == "Low":
            score += 5
            grade = "Low"
            insights.append("No critical OS issues detected—your setup appears stable.")
        else:
            insights.append("OS risk could not be determined.")

        # --- Password Check ---
        pw_summary = pw_results.get('summary', {})
        total_pw = pw_summary.get('total', 0)
        compromised_pw = pw_summary.get('compromised', 0)
        if compromised_pw > 0:
            score += min(30, compromised_pw * 5)
            insights.append(f"{compromised_pw} of {total_pw} saved passwords are weak or compromised.")
            recommendations.append("Change all weak/compromised passwords. Use at least 12 characters with symbols.")
        elif total_pw > 0:
            insights.append("No weak or compromised passwords detected.")
        else:
            insights.append("No saved passwords found.")

        # --- Permissions Check ---
        top_perm = perm_results.get('top_risks', [])
        risky_startup = [r for r in top_perm if r.get('risk', '') in ('High', 'Critical')]
        if risky_startup:
            score += min(20, len(risky_startup) * 5)
            insights.append(f"{len(risky_startup)} risky startup programs or permissions detected.")
            recommendations.append("Review and disable unnecessary startup programs and permissions.")
        else:
            insights.append("No risky startup programs detected.")

        # --- Final Score & Grade ---
        if score >= 70:
            grade = "Critical"
        elif score >= 50:
            grade = "High"
        elif score >= 25:
            grade = "Medium"
        else:
            grade = "Low"

        return {
            'score': min(100, score),
            'grade': grade,
            'health': health,
            'insights': insights,
            'recommendations': recommendations,
            'display': f"Risk Grade: {grade} (Score: {score}/100)"
        }
