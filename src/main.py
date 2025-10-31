#!/usr/bin/env python
# src/main.py
"""
Personal Device Security Advisor
-------------------------------
A unified security scanner that orchestrates multiple checks:
- OS security check (updates, security settings)
- Password breach check (saved browsers passwords & Wi-Fi profiles)
- Permissions & autostart check (suspicious autostart entries)

Run from project root: python -m src.main
"""

import sys
import json
import time
import argparse
import threading
import traceback
import os
import ctypes
import subprocess
from pathlib import Path
from typing import Dict, Any, Callable, TypeVar, Optional, List, cast
from concurrent.futures import ThreadPoolExecutor, Future
# Ensure src is in sys.path for imports
SRC_PATH = str(Path(__file__).resolve().parent)
if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)
# Integrate adaptive intelligence, anomaly detection, and trend visualizer
from ai import learning
from typing import TypeVar, Optional
from checks import os_check, password_check, permissions_check
T = TypeVar('T')

# ProgressIndicator class definition (move to top-level if not already)
class ProgressIndicator:
    def __init__(self, message: str, animation_type: str = "dots"):
        self.message = message
        self.animation_type = animation_type
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.animations = {
            "dots": [".", "..", "...", "...."],
            "spinner": ["-", "\\", "|", "/"],
            "bar": ["[    ]", "[=   ]", "[==  ]", "[=== ]", "[====]"],
        }
    def _animate(self):
        frames = self.animations.get(self.animation_type, self.animations["dots"])
        frame_count = len(frames)
        counter = 0
        sys.stdout.write(f"\n{self.message} ")
        sys.stdout.flush()
        while self.running:
            frame = frames[counter % frame_count]
            sys.stdout.write(f"{frame}\b" * len(frame))
            sys.stdout.flush()
            counter += 1
            time.sleep(0.25)
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._animate)
        self.thread.daemon = True
        self.thread.start()
    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
        sys.stdout.write("\n")
        sys.stdout.flush()
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLOR_ENABLED = True
    RISK_COLORS = {
        "Low": Fore.GREEN,
        "Medium": Fore.YELLOW,
        "High": Fore.RED,
        "Critical": Fore.RED + Style.BRIGHT,
        "NoPassword": Fore.WHITE,
        "Unknown": Fore.BLUE,
    }
except ImportError:
    COLOR_ENABLED = False
    class DummyFore:
        def __getattr__(self, name): return ""
    class DummyStyle:
        def __getattr__(self, name): return ""
    Fore = DummyFore()
    Style = DummyStyle()
    RISK_COLORS = {}
try:
    from src.ai import risk_analyzer
except ImportError:
    risk_analyzer = None

def main() -> None:
    # ...existing code...
    ai_health_status = "OK"
    ai_result = None
    try:
        scan_data = None
        # risk_analyzer is already imported at top-level; do not re-import or overwrite
        # Run checks and get results
        results = run_checks(parse_arguments())
        if risk_analyzer:
            scan_data = {
                "score": None,
                "risk_grade": "Unknown",
                "insights": [],
                "recommendations": []
            }
            # Build Gemini prompt using learning
            prompt = learning.build_gemini_prompt(scan_data)
            ai_result = risk_analyzer.analyze_risks(
                results.get("os", {}),
                results.get("passwords", {}),
                results.get("permissions", {}),
                fallback=False,
                latest_results=results
            )
            scan_data["score"] = ai_result.get("score", 0)
            scan_data["risk_grade"] = ai_result.get("grade", "Unknown")
            scan_data["insights"] = ai_result.get("insights", [])
            scan_data["recommendations"] = ai_result.get("recommendations", [])

            learning.save_scan(scan_data)
            anomalies = learning.detect_anomalies(scan_data)
            if anomalies:
                print("\n⚠️  Anomalies detected:")
                for a in anomalies:
                    print(" -", a)
            learning.show_trend()
        else:
            ai_health_status = "ERROR"
            ai_result = {"display": "AI risk analyzer not available.", "insights": [], "recommendations": []}
    except Exception as e:
        ai_health_status = "ERROR"
        ai_result = {"display": f"Error: {e}", "insights": [], "recommendations": []}

    # Ensure Fore and Style are imported
    try:
        from colorama import Fore, Style
    except ImportError:
        class DummyFore:
            def __getattr__(self, name): return ""
        class DummyStyle:
            def __getattr__(self, name): return ""
        Fore = DummyFore()
        Style = DummyStyle()

    print("\n" + "="*50)
    print(f"{Fore.MAGENTA}{Style.BRIGHT}AI Risk Analyzer Summary{Style.RESET_ALL}")
    print(f"Security AI Health: {ai_health_status}")
    print(ai_result['display'])
    print("\nInsights:")
    for insight in ai_result['insights']:
        print(" -", insight)
    print("\nRecommendations:")
    for rec in ai_result['recommendations']:
        print(" -", rec)
    print("="*50)

    return 0
    def __init__(self, message: str, animation_type: str = "dots"):
        """
        Initialize progress indicator with message and animation type.
        
        Args:
            message: Text to display before the animation
            animation_type: Type of animation ('dots', 'spinner', 'bar')
        """
        self.message = message
        self.animation_type = animation_type
        self.running = False
        self.thread: Optional[threading.Thread] = None
        
        # Animation frames for different types
        self.animations = {
            "dots": [".", "..", "...", "...."],
            "spinner": ["-", "\\", "|", "/"],
            "bar": ["[    ]", "[=   ]", "[==  ]", "[=== ]", "[====]"],
        }
        
    def _animate(self):
        """Animation thread function."""
        frames = self.animations.get(self.animation_type, self.animations["dots"])
        frame_count = len(frames)
        counter = 0
        
        # Print initial message
        sys.stdout.write(f"\n{self.message} ")
        sys.stdout.flush()
        
        while self.running:
            # Print frame and backspace
            frame = frames[counter % frame_count]
            sys.stdout.write(f"{frame}\b" * len(frame))
            sys.stdout.flush()
            counter += 1
            time.sleep(0.25)  # Animation speed
    
    def start(self):
        """Start the animation in a separate thread."""
        self.running = True
        self.thread = threading.Thread(target=self._animate)
        self.thread.daemon = True
        self.thread.start()
    
    def stop(self):
        """Stop the animation and clean up."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
        # Clear animation and move to next line
        sys.stdout.write("\n")
        sys.stdout.flush()

def run_with_progress(check_func: Callable[[], T], message: str) -> Optional[T]:
    """
    Run a check function with a progress indicator.
    
    Args:
        check_func: Function to run that returns check results
        message: Message to display during progress animation
        
    Returns:
        The return value of the check function or None if it fails
    """
    progress = ProgressIndicator(message)
    result = None
    error = None
    
    def run_check():
        nonlocal result, error
        try:
            result = check_func()
        except Exception as e:
            error = e
    
    # Start animation
    progress.start()
    
    # Run check in a separate thread
    thread = threading.Thread(target=run_check)
    thread.start()
    thread.join()
    
    # Stop animation
    progress.stop()
    
    # Handle errors
    if error:
        print(f"{Fore.RED}Error during {message}:{Style.RESET_ALL}")
        print(f"{Fore.RED}{error}{Style.RESET_ALL}")
        traceback.print_exc()
        return None
    
    return result

# ===============================
# Output Formatting Functions 
# ===============================
def colorize_risk(risk_level: str) -> str:
    """Apply color to risk level text if colors are enabled."""
    if not COLOR_ENABLED:
        return risk_level
    
    color = RISK_COLORS.get(risk_level, "")
    return f"{color}{risk_level}{Style.RESET_ALL}"

def print_risk(label: str, risk_level: str) -> None:
    """Print a label with color-coded risk level."""
    print(f"{label}: {colorize_risk(risk_level)}")

def print_section_header(title: str) -> None:
    """Print a formatted section header."""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'=' * 5} {title} {'=' * 5}{Style.RESET_ALL}\n")

def print_results_summary(results: Dict[str, Any]) -> None:
    """
    Print a formatted summary of scan results.
    
    Args:
        results: Combined dictionary of all check results
    """
    print_section_header("SECURITY SCAN SUMMARY")
    
    # OS Check Summary
    os_results = results.get("os", {})
    print_risk("OS Security Risk", os_results.get("overall_risk", "Unknown"))
    if "details" in os_results:
        print("OS Security Details:")
        for key, val in os_results.get("details", {}).items():
            if isinstance(val, dict) and "risk" in val:
                print(f"  - {key}: {colorize_risk(val['risk'])}")
            elif isinstance(val, str):
                print(f"  - {key}: {val}")
    
    # Password Check Summary
    pw_results = results.get("passwords", {})
    pw_summary = pw_results.get("summary", {})
    total = pw_summary.get("total", 0)
    compromised = pw_summary.get("compromised", 0)

    pw_risk = "Low"
    if compromised > 0:
        pw_risk = "High" if compromised > 5 else "Medium"

    print_risk(f"Password Risk ({compromised} of {total} compromised)", pw_risk)

    # Show all password check results
    print("\nPassword Check Results:")
    for entry in pw_results.get("results", []):
        risk = entry.get("risk", "Unknown")
        print(f"  - [{entry.get('browser')}/{entry.get('profile')}] {entry.get('origin')} ({entry.get('username')}) — Risk: {colorize_risk(risk)} — Breaches: {entry.get('breach_count')}")

    # Show top compromised items
    top_compromised = pw_results.get("top_compromised", [])
    if top_compromised:
        print("\nTop compromised passwords:")
        for c in top_compromised[:5]:  # Limit to 5
            if c.get("source") == "chrome":
                print(f"  - [chrome] {c.get('origin')} ({c.get('username')}) — {c.get('breach_count')} breaches")
    
    # Permissions Check Summary
    perm_results = results.get("permissions", {})
    top_perm_risks = perm_results.get("top_risks", [])
    if top_perm_risks:
        print_risk("Permissions/Startup Programs Risk", top_perm_risks[0].get("risk", "Unknown"))
        print("Top permission risks:")
        for r in top_perm_risks[:5]:  # Limit to 5
            reason = r.get("reason", "Potentially unwanted behavior.")
            print(f"  - {r.get('name')} [{r.get('source')}] Risk: {colorize_risk(r.get('risk'))} | Reason: {reason}")
    else:
        print_risk("Permissions/Startup Programs Risk", "Low")
        print("No concerning startup programs or permissions found.")
    
    print("\n" + "=" * 50)

# ===============================
# Main Program Logic
# ===============================
def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Personal Device Security Advisor - Scan your system for security vulnerabilities.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--limit", type=int, default=200, 
                       help="Limit passwords scanned per browser profile")
    parser.add_argument("--json", action="store_true", 
                       help="Output results in JSON format instead of formatted text")
    parser.add_argument("--checks", type=str, default="all",
                       help="Comma-separated list of checks to run: os,passwords,permissions or 'all'")
    
    return parser.parse_args()

def run_checks(args: argparse.Namespace) -> Dict[str, Any]:
    """
    Run all security checks based on command line arguments.
    
    Args:
        args: Parsed command line arguments
    
    Returns:
        Dictionary with combined results from all checks
    """
    results: Dict[str, Any] = {}
    
    # Determine which checks to run
    run_all = args.checks == "all"
    checks_to_run = args.checks.split(",") if args.checks != "all" else []
    
    # OS Check
    if run_all or "os" in checks_to_run:
        os_result = run_with_progress(
            os_check.evaluate_os_security,
            "Running OS security check"
        )
        results["os"] = os_result or {"overall_risk": "Unknown", "error": "Check failed"}
    
    # Password Check
    if run_all or "passwords" in checks_to_run:
        # Create parameter closure for password check
        def run_pw_check():
            return password_check.run_password_scan(
                limit_per_profile=args.limit,
            )
            
        pw_result = run_with_progress(
            run_pw_check,
            "Running password breach check"
        )
        results["passwords"] = pw_result or {"summary": {"total": 0, "compromised": 0}, "error": "Check failed"}
    
    # Permissions Check
    if run_all or "permissions" in checks_to_run:
        perm_result = run_with_progress(
            permissions_check.run_permissions_audit,
            "Running permissions & autostart check"
        )
        results["permissions"] = perm_result or {"top_risks": [], "error": "Check failed"}
    
    return results

def main() -> None:
    """Main entry point for the security scanner."""
    # Print banner
    print(f"{Fore.CYAN}{Style.BRIGHT}")
    print("=" * 50)
    print("   PERSONAL DEVICE SECURITY ADVISOR")
    print("=" * 50)
    print(f"{Style.RESET_ALL}")
    
    # Parse arguments
    args = parse_arguments()
    
    # Run all checks
    results = run_checks(args)

    # Output results
    if args.json:
        # JSON output mode
        print(json.dumps(results, indent=2, default=str))
    else:
        # Formatted text output
        print_results_summary(results)

    # Run AI risk analyzer and show results
    ai_health_status = "OK"
    ai_result = None
    try:
        if risk_analyzer:
            ai_result = risk_analyzer.analyze_risks(
                results.get("os", {}),
                results.get("passwords", {}),
                results.get("permissions", {})
            )
            ai_health_status = ai_result.get('health', 'OK')
        else:
            raise ImportError("risk_analyzer not available")
    except Exception as e:
        # Fallback to local analyzer logic in risk_analyzer.py
        ai_result = risk_analyzer.analyze_risks(
            results.get("os", {}),
            results.get("passwords", {}),
            results.get("permissions", {}),
            fallback=True
        )
        ai_health_status = ai_result.get('health', 'FALLBACK MODE')
        print("\nGemini AI unavailable—using local analyzer.")

    # Print AI health status
    print("\n" + "="*50)
    print(f"{Fore.MAGENTA}{Style.BRIGHT}AI Risk Analyzer Summary{Style.RESET_ALL}")
    print(f"Security AI Health: {ai_health_status}")
    print(ai_result['display'])
    print("\nInsights:")
    for insight in ai_result['insights']:
        print(f"- {insight}")
    print("\nRecommendations:")
    for rec in ai_result['recommendations']:
        print(f"* {rec}")
    print("="*50)

    # Log AI health status to local file
    try:
        with open("ai_health.log", "a", encoding="utf-8") as logf:
            logf.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] AI Health: {ai_health_status}\n")
    except Exception:
        pass

    return 0

if __name__ == "__main__":
    sys.exit(main())
