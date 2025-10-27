
"""
Unified AI Risk Analyzer for Personal Device Security Advisor
------------------------------------------------------------
Analyzes outputs from OS, password, and permissions checks to generate a risk score and actionable recommendations.
Includes both Gemini (primary) and LocalRiskAnalyzer (fallback) logic. Operates fully locally if needed.
"""

"""
Unified AI Risk Analyzer for Personal Device Security Advisor
------------------------------------------------------------
Analyzes outputs from OS, password, and permissions checks to generate a risk score and actionable recommendations.
Supports Google Gemini API for natural language analysis, with automatic fallback to local backup analyzer.
"""
import os
import json
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

# --- Utility Functions ---
def colorize(text, risk):
    if not COLOR_ENABLED: return text
    if risk == "Critical": return f"{Fore.RED}{Style.BRIGHT}{text}{Style.RESET_ALL}"
    if risk == "High": return f"{Fore.RED}{text}{Style.RESET_ALL}"
    if risk == "Medium": return f"{Fore.YELLOW}{text}{Style.RESET_ALL}"
    if risk == "Low": return f"{Fore.GREEN}{text}{Style.RESET_ALL}"
    return text

# --- Gemini API Integration ---
def _get_gemini_api_key():
    # Load API key from .env
    api_key = None
    env_path = os.path.join(os.path.dirname(__file__), '../../.env')
    if os.path.exists(env_path):
        with open(env_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip().startswith('GEMINI_API_KEY='):
                    api_key = line.strip().split('=', 1)[1]
                    break
    return api_key

def _install_google_genai():
    try:
        import google.generativeai
    except ImportError:
        import subprocess
        subprocess.run([os.sys.executable, '-m', 'pip', 'install', 'google-generativeai'], check=True)
        # Add to requirements.txt
        req_path = os.path.join(os.path.dirname(__file__), '../../requirements.txt')
        with open(req_path, 'a', encoding='utf-8') as reqf:
            reqf.write('\ngoogle-generativeai\n')

# --- Main Analyzer ---
def analyze_risks(os_results: Dict[str, Any], pw_results: Dict[str, Any],
                  perm_results: Dict[str, Any], fallback: bool = False) -> Dict[str, Any]:
    """
    Analyze device security risks and return a structured assessment.
    Uses Gemini API unless fallback=True or API fails.
    Returns a dict:
    {
        'score': float,
        'grade': str,
        'color': str,
        'health': str,
        'insights': List[str],
        'recommendations': List[str],
        'display': str
    }
    """

    # --- Prepare sanitized input ---
    sanitized = {
        'os_risk': os_results.get('overall_risk', 'Unknown'),
        'os_patch': os_results.get('details', {}).get('patch_level', 'Unknown'),
        'os_update': os_results.get('details', {}).get('recent_update', 'Unknown'),
        'pw_total': pw_results.get('summary', {}).get('total', 0),
        'pw_compromised': pw_results.get('summary', {}).get('compromised', 0),
        'perm_top_risks': [r.get('risk', 'Unknown') for r in perm_results.get('top_risks', [])],
        'perm_risk_count': len([r for r in perm_results.get('top_risks', [])
                                if r.get('risk', '') in ('High', 'Critical')]),
    }

    # --- Try Gemini API ---
    if not fallback:
        api_key = _get_gemini_api_key()
        if api_key:
            try:
                _install_google_genai()
                import google.generativeai as genai
                genai.configure(api_key=api_key)

                prompt = (
                    f"Device Security Summary:\n"
                    f"- OS risk: {sanitized['os_risk']}\n"
                    f"- Patch level: {sanitized['os_patch']}\n"
                    f"- Last update: {sanitized['os_update']}\n"
                    f"- Total passwords: {sanitized['pw_total']}\n"
                    f"- Compromised passwords: {sanitized['pw_compromised']}\n"
                    f"- Startup/permission risks: {sanitized['perm_top_risks']}\n"
                    f"- Number of high/critical permission risks: {sanitized['perm_risk_count']}\n\n"
                    "Respond exactly in JSON with the keys: "
                    '"score" (0-100), "grade" (Low/Medium/High/Critical), '
                    '"insights" (2-5 strings), "recommendations" (2-5 strings). '
                    "Do NOT include any personal info, passwords, URLs, or Wi-Fi SSIDs. "
                    "\n\n"
                    "Additional instructions to make this analysis advanced:\n"
                    "1. Consider cross-factor security risks, such as how outdated OS patches could amplify password vulnerabilities.\n"
                    "2. Highlight anomalies or unexpected patterns, e.g., unusually high permission risks relative to total apps.\n"
                    "3. Prioritize actionable advice that is specific, concrete, and feasible for an average user.\n"
                    "4. When scoring, weigh critical risks more heavily than minor risks, and reflect this in both 'score' and 'grade'.\n"
                    "5. Format all lists in insights and recommendations as concise, 1-2 sentence statements.\n"
                    "6. Include at least one advanced recommendation that goes beyond typical device checkers, "
                    "such as suggestions for proactive monitoring or cross-platform security practices.\n"
                    "\nOptional: You may add a 'confidence' key (0-100) representing how confident the analysis is based on the data provided."
                )

                model = genai.GenerativeModel('gemini-2.0-flash-lite')
                response = model.generate_content(prompt)

                # --- Parse Gemini JSON ---
                try:
                    ai_data = json.loads(response.text)
                except json.JSONDecodeError:
                    import re
                    match = re.search(r'\{.*\}', response.text, re.DOTALL)
                    if match:
                        ai_data = json.loads(match.group(0))
                    else:
                        ai_data = {'score': None, 'grade': 'Low', 'insights': [], 'recommendations': []}

                # Ensure valid output
                score = ai_data.get('score', 0)
                grade = ai_data.get('grade', 'Low')
                insights = ai_data.get('insights') or ["No insights available."]
                recommendations = ai_data.get('recommendations') or ["No recommendations available."]
                color = grade if grade in ('Low','Medium','High','Critical') else 'Low'

                return {
                    'score': score,
                    'grade': grade,
                    'color': color,
                    'health': 'OK',
                    'insights': insights,
                    'recommendations': recommendations,
                    'display': colorize(f"Risk Grade: {grade} (Score: {score})", color)
                }

            except Exception:
                pass  # fallback below

    # --- Local Backup Analyzer ---
    score = 0
    grade = "Low"
    health = "FALLBACK MODE"
    insights: List[str] = []
    recommendations: List[str] = []

    # OS Risk
    os_risk = sanitized['os_risk']
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
        insights.append("No critical OS issues detected—your setup appears stable.")
    else:
        insights.append("OS risk could not be determined.")

    # Password Risk
    pw_total = sanitized['pw_total']
    pw_compromised = sanitized['pw_compromised']
    if pw_compromised > 0:
        score += min(30, pw_compromised * 5)
        insights.append(f"{pw_compromised} of {pw_total} saved passwords are weak or compromised.")
        recommendations.append("Change all weak/compromised passwords. Use at least 12 characters with symbols.")
    elif pw_total > 0:
        insights.append("No weak or compromised passwords detected.")
    else:
        insights.append("No saved passwords found.")

    # Permissions Risk
    perm_risk_count = sanitized['perm_risk_count']
    if perm_risk_count > 0:
        score += min(20, perm_risk_count * 5)
        insights.append(f"{perm_risk_count} risky startup programs or permissions detected.")
        recommendations.append("Review and disable unnecessary startup programs and permissions.")
    else:
        insights.append("No risky startup programs detected.")

    # Final Grade
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
        'color': grade,
        'health': health,
        'insights': insights,
        'recommendations': recommendations,
        'display': colorize(f"Risk Grade: {grade} (Score: {score}/100)", grade)
    }


