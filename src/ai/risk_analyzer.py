import os
import json
import datetime
from . import learning
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
    if not COLOR_ENABLED:
        return text
    if risk == "Critical":
        return f"{Fore.RED}{Style.BRIGHT}{text}{Style.RESET_ALL}"
    if risk == "High":
        return f"{Fore.RED}{text}{Style.RESET_ALL}"
    if risk == "Medium":
        return f"{Fore.YELLOW}{text}{Style.RESET_ALL}"
    if risk == "Low":
        return f"{Fore.GREEN}{text}{Style.RESET_ALL}"
    return text


HISTORY_PATH = os.path.join(os.path.dirname(__file__), '../../data/risk_history.json')
HISTORY_MAX = 10

# --- Risk History Management ---
HISTORY_PATH = os.path.join(os.path.dirname(__file__), '../../data/risk_history.json')
HISTORY_MAX = 10

def load_risk_history():
    return learning.load_history()

def save_risk_history(history: list):
    try:
        with open(HISTORY_PATH, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=2)
    except Exception:
        pass

def append_risk_history(entry: dict):
    # Enrich with categories and prune
    entry = learning.enrich_entry_with_categories(entry)
    learning.append_and_prune(entry)

# --- Contextual Payload Builder ---
def build_contextual_payload(latest_results: dict, history: list) -> dict:
    # Use learning module for trend and categories
    _, cat_summary, trend_info = learning.get_history_and_trends()
    payload = {
        'current': {
            'timestamp': datetime.datetime.now().isoformat(),
            'os_risk': latest_results.get('os', {}).get('overall_risk', 'Unknown'),
            'os_patch': latest_results.get('os', {}).get('details', {}).get('patch_level', 'Unknown'),
            'os_update': latest_results.get('os', {}).get('details', {}).get('recent_update', 'Unknown'),
            'pw_total': latest_results.get('passwords', {}).get('summary', {}).get('total', 0),
            'pw_compromised': latest_results.get('passwords', {}).get('summary', {}).get('compromised', 0),
            'perm_top_risks': [r.get('risk', 'Unknown') for r in latest_results.get('permissions', {}).get('top_risks', [])],
            'perm_risk_count': len([r for r in latest_results.get('permissions', {}).get('top_risks', []) if r.get('risk', '') in ('High', 'Critical')]),
        },
        'history': history[-HISTORY_MAX:],
        'trend': trend_info,
        'category_summary': cat_summary
    }
    return payload

# --- Predictive Analysis Helper ---
def run_predictive_analysis(latest_results: dict) -> dict:
    sim_pw = dict(latest_results)
    if 'passwords' in sim_pw:
        sim_pw['passwords'] = dict(sim_pw['passwords'])
        sim_pw['passwords']['summary'] = dict(sim_pw['passwords'].get('summary', {}))
        sim_pw['passwords']['summary']['compromised'] = 0
    sim_os = dict(latest_results)
    if 'os' in sim_os:
        sim_os['os'] = dict(sim_os['os'])
        sim_os['os']['overall_risk'] = 'Low'
        sim_os['os']['details'] = dict(sim_os['os'].get('details', {}))
        sim_os['os']['details']['patch_level'] = 'Up-to-date'
        sim_os['os']['details']['recent_update'] = 'Today'
    return {
        'all_passwords_secure': sim_pw,
        'os_fully_patched': sim_os
    }

# --- OpenRouter API Integration ---
def _get_openrouter_api_key():
    api_key = None
    env_path = os.path.join(os.path.dirname(__file__), '../../.env')
    if os.path.exists(env_path):
        with open(env_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip().startswith('OPENROUTER_API_KEY='):
                    api_key = line.strip().split('=', 1)[1]
                    break
    return api_key

def _install_openai():
    try:
        import openai
    except ImportError:
        import subprocess
        subprocess.run([os.sys.executable, '-m', 'pip', 'install', 'openai'], check=True)
        req_path = os.path.join(os.path.dirname(__file__), '../../requirements.txt')
        with open(req_path, 'a', encoding='utf-8') as reqf:
            reqf.write('\nopenai\n')
def load_risk_history():
    if not os.path.exists(HISTORY_PATH):
        return []
    try:
        with open(HISTORY_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []

def save_risk_history(history: list):
    try:
        with open(HISTORY_PATH, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=2)
    except Exception:
        pass

# --- Main Analyzer ---
def analyze_risks(
    os_results: Dict[str, Any],
    pw_results: Dict[str, Any],
    perm_results: Dict[str, Any],
    fallback: bool = False,
    latest_results: dict = None
) -> Dict[str, Any]:
    """
    Analyze device security risks and return a structured assessment.
    Uses OpenRouter API unless fallback=True or API fails.
    Returns a dict with contextual and predictive analysis.
    """
    # --- Adaptive Intelligence Integration ---
    from . import learning
    import traceback
    import logging
    LOG_PATH = os.path.join(os.path.dirname(__file__), '../../ai_health.log')
    def log_health_event(event: str):
        try:
            with open(LOG_PATH, 'a', encoding='utf-8') as logf:
                logf.write(f"[{datetime.datetime.now().isoformat()}] {event}\n")
        except Exception:
            pass

    sanitized = {
        'os_risk': os_results.get('overall_risk', 'Unknown'),
        'os_patch': os_results.get('details', {}).get('patch_level', 'Unknown'),
        'os_update': os_results.get('details', {}).get('recent_update', 'Unknown'),
        'pw_total': pw_results.get('summary', {}).get('total', 0),
        'pw_compromised': pw_results.get('summary', {}).get('compromised', 0),
        'perm_top_risks': [r.get('risk', 'Unknown') for r in perm_results.get('top_risks', [])],
        'perm_risk_count': len([r for r in perm_results.get('top_risks', []) if r.get('risk', '') in ('High', 'Critical')]),
    }
    history_entry = {
        'timestamp': datetime.datetime.now().isoformat(),
        'score': None,
        'grade': None,
        'os_risk': sanitized['os_risk'],
        'pw_compromised': sanitized['pw_compromised'],
        'perm_risk_count': sanitized['perm_risk_count'],
        'insights': [],
        'recommendations': []
    }
    history = load_risk_history()
    predictive = run_predictive_analysis(latest_results or {'os': os_results, 'passwords': pw_results, 'permissions': perm_results})
    contextual_payload = build_contextual_payload(latest_results or {'os': os_results, 'passwords': pw_results, 'permissions': perm_results}, history)
    contextual_payload['predictive'] = predictive

    # --- Adaptive Prompt Engineering ---
    try:
        adaptive_context = learning.get_adaptive_prompt_context(history, sanitized)
    except Exception as e:
        adaptive_context = None
        log_health_event(f"Adaptive context error: {e}")

    # --- Fallback Chain: OpenRouter → Offline Predictor → Hardcoded Fallback ---
    # 1. Try OpenRouter
    if not fallback:
        api_key = _get_openrouter_api_key()
        if api_key:
            try:
                _install_openai()
                from openai import OpenAI
                client = OpenAI(
                    base_url="https://openrouter.ai/api/v1",
                    api_key=api_key,
                )
                prompt = learning.compose_gemini_prompt(contextual_payload, adaptive_context)
                response = client.chat.completions.create(
                    model="x-ai/grok-4.1-fast",
                    messages=[
                        {"role": "user", "content": prompt}
                    ]
                )
                import re
                import ast
                text = response.choices[0].message.content.strip()
                match = re.search(r'\{[\s\S]*\}', text)
                if match:
                    json_str = match.group(0)
                    try:
                        result = json.loads(json_str)
                    except Exception:
                        result = ast.literal_eval(json_str)
                else:
                    try:
                        result = json.loads(text)
                    except Exception:
                        result = ast.literal_eval(text)
                score = float(result.get('score', 0))
                grade = result.get('grade', 'Low')
                insights = result.get('insights', [])
                recommendations = result.get('recommendations', [])
                predictive_suggestions = result.get('predictive', [])
                display = colorize(f"Risk Grade: {grade} (Score: {score}/100)", grade)
                history_entry['score'] = score
                history_entry['grade'] = grade
                history_entry['insights'] = insights
                history_entry['recommendations'] = recommendations
                append_risk_history(history_entry)
                log_health_event("OpenRouter success")
                return {
                    'score': score,
                    'grade': grade,
                    'color': grade,
                    'health': 'OK',
                    'insights': insights,
                    'recommendations': recommendations,
                    'predictive': predictive_suggestions,
                    'display': display
                }
            except Exception as e:
                log_health_event(f"OpenRouter failure: {e}\n{traceback.format_exc()}")

    # 2. Try Offline Predictor
    try:
        offline_pred = learning.predict_next_risk(history, sanitized)
        if offline_pred:
            score = float(offline_pred.get('score', 0))
            grade = offline_pred.get('grade', 'Low')
            insights = offline_pred.get('insights', [])
            recommendations = offline_pred.get('recommendations', [])
            predictive_suggestions = offline_pred.get('predictive', [])
            display = colorize(f"Risk Grade: {grade} (Score: {score}/100)", grade)
            history_entry['score'] = score
            history_entry['grade'] = grade
            history_entry['insights'] = insights
            history_entry['recommendations'] = recommendations
            append_risk_history(history_entry)
            log_health_event("Offline predictor success")
            return {
                'score': score,
                'grade': grade,
                'color': grade,
                'health': 'OFFLINE_PREDICTOR',
                'insights': insights,
                'recommendations': recommendations,
                'predictive': predictive_suggestions,
                'display': display
            }
    except Exception as e:
        log_health_event(f"Offline predictor failure: {e}\n{traceback.format_exc()}")

    # 3. Hardcoded Fallback
    try:
        score = 0
        grade = "Low"
        health = "HARDCODED_FALLBACK"
        insights: List[str] = []
        recommendations: List[str] = []
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
        perm_risk_count = sanitized['perm_risk_count']
        if perm_risk_count > 0:
            score += min(20, perm_risk_count * 5)
            insights.append(f"{perm_risk_count} risky startup programs or permissions detected.")
            recommendations.append("Review and disable unnecessary startup programs and permissions.")
        else:
            insights.append("No risky startup programs detected.")
        if score >= 70:
            grade = "Critical"
        elif score >= 50:
            grade = "High"
        elif score >= 25:
            grade = "Medium"
        else:
            grade = "Low"
        history_entry['score'] = min(100, score)
        history_entry['grade'] = grade
        history_entry['insights'] = insights
        history_entry['recommendations'] = recommendations
        append_risk_history(history_entry)
        log_health_event("Hardcoded fallback used")
        return {
            'score': min(100, score),
            'grade': grade,
            'color': grade,
            'health': health,
            'insights': insights,
            'recommendations': recommendations,
            'predictive': [],
            'display': colorize(f"Risk Grade: {grade} (Score: {score}/100)", grade)
        }
    except Exception as e:
        log_health_event(f"Hardcoded fallback failure: {e}\n{traceback.format_exc()}")
        return {
            'score': 0,
            'grade': 'Low',
            'color': 'Low',
            'health': 'ERROR',
            'insights': ["Risk analysis failed."],
            'recommendations': ["Try again or check logs."],
            'predictive': [],
            'display': colorize("Risk Grade: Low (Score: 0/100)", 'Low')
        }

"""
Unified AI Risk Analyzer for Personal Device Security Advisor
------------------------------------------------------------
Analyzes outputs from OS, password, and permissions checks to generate a risk score and actionable recommendations.
"""

"""
Includes both OpenRouter (primary) and LocalRiskAnalyzer (fallback) logic. Operates fully locally if needed.
"""

"""
Unified AI Risk Analyzer for Personal Device Security Advisor
------------------------------------------------------------
Analyzes outputs from OS, password, and permissions checks to generate a risk score and actionable recommendations.
Supports OpenRouter API for natural language analysis, with automatic fallback to local backup analyzer.
"""
import os
import json
import datetime
from typing import Dict, Any, List

# Optional color output
try:
    from colorama import Fore, Style
    COLOR_ENABLED = True
except ImportError:
    COLOR_ENABLED = False
    class DummyFore:
        # --- Main Analyzer ---
        def analyze_risks(
            os_results: Dict[str, Any],
            pw_results: Dict[str, Any],
            perm_results: Dict[str, Any],
            fallback: bool = False,
            latest_results: dict = None
        ) -> Dict[str, Any]:
            """
            Analyze device security risks and return a structured assessment.
            Uses OpenRouter API unless fallback=True or API fails.
            Returns a dict:
            {
                'score': float,
                'grade': str,
                'color': str,
                'health': str,
                'insights': List[str],
                'recommendations': List[str],
                'predictive': List[str],
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
                'perm_risk_count': len([r for r in perm_results.get('top_risks', []) if r.get('risk', '') in ('High', 'Critical')]),
            }

            # --- Risk History Integration ---
            history_entry = {
                'timestamp': datetime.datetime.now().isoformat(),
                'score': None,  # Will be filled after analysis
                'grade': None,  # Will be filled after analysis
                'os_risk': sanitized['os_risk'],
                'pw_compromised': sanitized['pw_compromised'],
                'perm_risk_count': sanitized['perm_risk_count'],
                'insights': [],
                'recommendations': []
            }
            history = load_risk_history()

            # --- Predictive Analysis ---
            predictive = run_predictive_analysis(latest_results or {'os': os_results, 'passwords': pw_results, 'permissions': perm_results})

            # --- Contextual Payload ---
            contextual_payload = build_contextual_payload(latest_results or {'os': os_results, 'passwords': pw_results, 'permissions': perm_results}, history)
            contextual_payload['predictive'] = predictive

            # --- Try OpenRouter API ---
            if not fallback:
                api_key = _get_openrouter_api_key()
                if api_key:
                    try:
                        _install_openai()
                        from openai import OpenAI
                        client = OpenAI(
                            base_url="https://openrouter.ai/api/v1",
                            api_key=api_key,
                        )

                        prompt = (
                            "You are a cybersecurity intelligence model. Analyze the current and historical device risk data, correlate patterns, and provide trend-aware insights and predictive advice.\n"
                            f"Current and historical risk data (JSON):\n{json.dumps(contextual_payload, indent=2)}\n"
                            "Instructions:\n"
                            "- Provide 2–5 insights linking multiple risk vectors (e.g., how OS risk and password risk interact).\n"
                            "- Provide 2–5 actionable recommendations.\n"
                            "- Provide 1–2 predictive suggestions (e.g., 'If passwords were all secure, risk would drop to X').\n"
                            "- Respond exactly in JSON with the keys: 'score' (0-100), 'grade' (Low/Medium/High/Critical), 'insights' (2-5 strings), 'recommendations' (2-5 strings), 'predictive' (1-2 strings).\n"
                            "- Do NOT include any personal info, passwords, URLs, or Wi-Fi SSIDs.\n"
                            "- If history is present, highlight trends (improving, declining, stable).\n"
                            "- If parsing fails, fallback to local analysis.\n"
                        )

                        response = client.chat.completions.create(
                            model="google/gemini-2.0-flash-exp:free",
                            messages=[
                                {"role": "user", "content": prompt}
                            ]
                        )
                        import re
                        import ast
                        text = response.choices[0].message.content.strip()
                        match = re.search(r'\{[\s\S]*\}', text)
                        if match:
                            json_str = match.group(0)
                            try:
                                result = json.loads(json_str)
                            except Exception:
                                result = ast.literal_eval(json_str)
                        else:
                            try:
                                result = json.loads(text)
                            except Exception:
                                result = ast.literal_eval(text)

                        score = float(result.get('score', 0))
                        grade = result.get('grade', 'Low')
                        insights = result.get('insights', [])
                        recommendations = result.get('recommendations', [])
                        predictive_suggestions = result.get('predictive', [])
                        display = colorize(f"Risk Grade: {grade} (Score: {score}/100)", grade)

                        # Save to history
                        history_entry['score'] = score
                        history_entry['grade'] = grade
                        history_entry['insights'] = insights
                        history_entry['recommendations'] = recommendations
                        append_risk_history(history_entry)

                        return {
                            'score': score,
                            'grade': grade,
                            'color': grade,
                            'health': 'OK',
                            'insights': insights,
                            'recommendations': recommendations,
                            'predictive': predictive_suggestions,
                            'display': display
                        }
                    except Exception:
                        pass  # fallback below

def _install_openai():
    try:
        import openai
    except ImportError:
        import subprocess
        subprocess.run([os.sys.executable, '-m', 'pip', 'install', 'openai'], check=True)
        # Add to requirements.txt
        req_path = os.path.join(os.path.dirname(__file__), '../../requirements.txt')
        with open(req_path, 'a', encoding='utf-8') as reqf:
            reqf.write('\nopenai\n')


    # --- Local Backup Analyzer ---
    # This block is only used if OpenRouter API is not available or fallback is True
    def local_backup_analyzer(os_results, pw_results, perm_results):
        score = 0
        grade = "Low"
        health = "FALLBACK MODE"
        insights: List[str] = []
        recommendations: List[str] = []

        # OS Risk
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
            insights.append("No critical OS issues detected—your setup appears stable.")
        else:
            insights.append("OS risk could not be determined.")

        # Password Risk
        pw_total = pw_results.get('summary', {}).get('total', 0)
        pw_compromised = pw_results.get('summary', {}).get('compromised', 0)
        if pw_compromised > 0:
            score += min(30, pw_compromised * 5)
            insights.append(f"{pw_compromised} of {pw_total} saved passwords are weak or compromised.")
            recommendations.append("Change all weak/compromised passwords. Use at least 12 characters with symbols.")
        elif pw_total > 0:
            insights.append("No weak or compromised passwords detected.")
        else:
            insights.append("No saved passwords found.")

        # Permissions Risk
        perm_risk_count = len([r for r in perm_results.get('top_risks', []) if r.get('risk', '') in ('High', 'Critical')])
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