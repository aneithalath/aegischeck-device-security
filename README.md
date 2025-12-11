# AegisCheck

**AI-Powered Device Security Scanner**

AegisCheck is a comprehensive, AI-driven tool for assessing and improving the security posture of your personal computer. It combines traditional security checks with advanced AI analysis to provide actionable insights and recommendations—all from your own device, with no sensitive data sent to the cloud.

---

## 🚀 Features

- **Unified Security Scanning**: Checks your operating system, saved browser passwords, and startup/permissions for vulnerabilities and risks.
- **AI Risk Analyzer**: Uses Grok 4.1 Fast (with an adaptive offline AI fallback that learns from previous results) to analyze your device's risk profile, trends, and provide tailored recommendations.
- **Actionable Insights**: Presents clear, prioritized security advice and predictive suggestions for reducing your risk.
- **Modern CLI & GUI**: Run from the command line or enjoy a beautiful Streamlit dashboard—your choice.
- **Privacy-First**: All analysis is performed locally. No passwords or sensitive data leave your machine.

---

## 🖥️ Quick Start

### 1. Install Requirements

Install all dependencies (Python 3.9+ recommended):

```bash
pip install -r requirements.txt
```

### 2. Run the CLI (Command Line)

Launch a full security scan and AI analysis from your terminal:

```bash
python -m src.main
```

You’ll see a detailed summary of OS, password, and permissions risks, plus AI-powered insights and recommendations.

### 3. Run the GUI (Streamlit Dashboard)

Enjoy a modern, interactive dashboard with expanders and detailed results:

```bash
streamlit run app.py
```

Use the sidebar to navigate between the Dashboard Overview and Detailed Results. Click “Run Full Scan” to start a new analysis.

---

## 🛡️ What Does It Check?

- **OS Security**: Patch status, firewall, Defender, admin/UAC, and more.
- **Passwords**: Scans saved browser credentials for breaches (using k-anonymity, never sending real passwords).
- **Permissions & Startup**: Flags risky startup programs, background services, and suspicious permissions.
- **AI Risk Analysis**: Correlates all findings, detects trends, and predicts future risk using Grok 4.1 Fast or an adaptive offline AI that learns from your device's risk history to enhance new results.

---

## 📋 Requirements

- Python 3.9 or newer
- All required libraries are listed in `requirements.txt`
- For full AI features, a Grok 4.1 Fast API key (optional; otherwise, the adaptive offline AI is used)

---

## 🧑‍💻 Project Structure

- `src/main.py` — Main CLI entry point
- `app.py` — Streamlit GUI
- `src/ai/` — AI logic, risk analyzer, learning modules
- `src/checks/` — OS, password, and permissions checkers
- `data/` — Local cache and risk history

---

## 💡 Why Use This Project?

- **All-in-one**: No need for multiple tools—get a holistic view of your device’s security in one scan.
- **AI-Driven**: Leverages state-of-the-art AI for deeper, more adaptive analysis.
- **User-Friendly**: Both CLI and GUI are easy to use, with clear output and actionable advice.
- **Open Source**: Fully transparent, extensible, and privacy-respecting.

---

## 📝 Example Usage

**CLI Example:**

```
$ python -m src.main
==================================================
	AEGISCHECK
==================================================
OS Security Risk: Low
Password Risk (3 of 100 compromised): Medium
Permissions/Startup Programs Risk: Low
... (AI insights and recommendations follow)
==================================================
```

**GUI Example:**

1. Run `streamlit run app.py`
2. Click “Run Full Scan”
3. View results in Dashboard Overview and Detailed Results pages

---

## 🤝 Contributing

Pull requests and suggestions are welcome! Please open an issue or PR if you have ideas or improvements.

---
