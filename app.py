import streamlit as st
import sys
import traceback
from pathlib import Path
import os
import time

#Run with `streamlit run app.py`

# Ensure src is in sys.path for imports
SRC_PATH = str(Path(__file__).resolve().parent / "src")
if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)

from src.main import run_checks
from src.ai import risk_analyzer
from src.ai import learning

# Default args to match main.py
class Args:
    limit = 200
    json = False
    checks = "all"

def run_full_scan():
    args = Args()
    results = run_checks(args)
    ai_result = None
    ai_health_status = "OK"
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
        ai_result = risk_analyzer.analyze_risks(
            results.get("os", {}),
            results.get("passwords", {}),
            results.get("permissions", {}),
            fallback=True
        )
        ai_health_status = ai_result.get('health', 'FALLBACK MODE')
    return results, ai_result, ai_health_status

# Streamlit App
st.set_page_config(page_title="AegisCheck", layout="wide")
st.title("AegisCheck - Device Security Advisor")

# Sidebar navigation
page = st.sidebar.radio("Navigation", ["Dashboard Overview", "Detailed Results"])

if 'scan_results' not in st.session_state:
    st.session_state['scan_results'] = None
    st.session_state['ai_result'] = None
    st.session_state['ai_health_status'] = None

if st.button("Run Full Scan"):
    with st.spinner("Running full device security scan..."):
        try:
            results, ai_result, ai_health_status = run_full_scan()
            st.session_state['scan_results'] = results
            st.session_state['ai_result'] = ai_result
            st.session_state['ai_health_status'] = ai_health_status
        except Exception as e:
            st.error(f"Scan failed: {e}")
            st.session_state['scan_results'] = None
            st.session_state['ai_result'] = None
            st.session_state['ai_health_status'] = None
            st.session_state['traceback'] = traceback.format_exc()

results = st.session_state.get('scan_results')
ai_result = st.session_state.get('ai_result')
ai_health_status = st.session_state.get('ai_health_status')

if page == "Dashboard Overview":
    st.header("Dashboard Overview")
    if results and ai_result:
        with st.expander("OS Security Summary", expanded=True):
            os_results = results.get("os", {})
            st.write(f"**OS Security Risk:** {os_results.get('overall_risk', 'Unknown')}")
            if "details" in os_results:
                st.json(os_results["details"])
            if os_results.get("error"):
                st.error(os_results["error"])
        with st.expander("Password Summary", expanded=True):
            pw_results = results.get("passwords", {})
            pw_summary = pw_results.get("summary", {})
            st.write(f"**Total Passwords:** {pw_summary.get('total', 0)}")
            st.write(f"**Compromised Passwords:** {pw_summary.get('compromised', 0)}")
            if pw_results.get("error"):
                st.error(pw_results["error"])
        with st.expander("Permissions Summary", expanded=True):
            perm_results = results.get("permissions", {})
            top_perm_risks = perm_results.get("top_risks", [])
            if top_perm_risks:
                st.write(f"**Top Permission Risk:** {top_perm_risks[0].get('risk', 'Unknown')}")
                st.json(top_perm_risks)
            else:
                st.write("No concerning startup programs or permissions found.")
            if perm_results.get("error"):
                st.error(perm_results["error"])
        with st.expander("AI Risk Analysis", expanded=True):
            st.write(f"**AI Health Status:** {ai_health_status}")
            st.write(f"**Risk Grade:** {ai_result.get('grade', 'Unknown')} (Score: {ai_result.get('score', 'N/A')}/100)")
            st.write("**Insights:**")
            for insight in ai_result.get('insights', []):
                st.markdown(f"- {insight}")
            st.write("**Recommendations:**")
            for rec in ai_result.get('recommendations', []):
                st.markdown(f"* {rec}")
            if ai_result.get('display'):
                st.info(ai_result['display'])
    elif 'scan_results' in st.session_state and st.session_state['scan_results'] is None:
        st.info("Click 'Run Full Scan' to begin.")
    else:
        st.info("Click 'Run Full Scan' to begin.")

elif page == "Detailed Results":
    st.header("Detailed Results")
    if results:
        with st.expander("OS Security Details", expanded=False):
            os_results = results.get("os", {})
            st.json(os_results)
        with st.expander("Password Details", expanded=False):
            pw_results = results.get("passwords", {})
            st.json(pw_results)
        with st.expander("Permissions Details", expanded=False):
            perm_results = results.get("permissions", {})
            st.json(perm_results)
        if ai_result:
            with st.expander("AI Risk Analyzer Raw Output", expanded=False):
                st.json(ai_result)
    else:
        st.info("No scan results yet. Run a scan to see details.")

# Optionally, show trend or anomaly info
# Uncomment below if you want to display trend/anomaly info visually
# if ai_result:
#     anomalies = learning.detect_anomalies(ai_result)
#     if anomalies:
#         st.warning("Anomalies detected:")
#         for a in anomalies:
#             st.write(f"- {a}")
#     # learning.show_trend() # Could be visualized if implemented for Streamlit
