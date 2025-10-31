import os, json, datetime

HISTORY_FILE = os.path.join(os.path.dirname(__file__), '../../data/risk_history.json')

def load_history():
    """Load historical scan data from JSON file."""
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []

def save_scan(scan_data):
    """Save new scan results with timestamp to history file."""
    os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
    history = load_history()
    scan_data["timestamp"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    history.append(scan_data)
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)

def get_profile():
    """Compute basic adaptive intelligence stats from history."""
    history = load_history()
    if not history:
        return {"avg_score": None, "total_scans": 0, "last_score": None}
    scores = [h.get("score", 0) for h in history if isinstance(h.get("score"), (int, float))]
    avg_score = round(sum(scores) / len(scores), 2)
    last_score = scores[-1]
    return {"avg_score": avg_score, "total_scans": len(scores), "last_score": last_score}

def detect_anomalies(current_data):
    """Detect anomalies based on deviation from previous score."""
    history = load_history()
    anomalies = []
    if len(history) < 1:
        anomalies.append("No previous scans to compare against.")
        return anomalies
    prev_score = history[-1].get("score", 0)
    curr_score = current_data.get("score", 0)
    diff = abs(curr_score - prev_score)
    if diff > 20:
        anomalies.append(f"⚠️  Risk score changed by {diff} points since last scan.")
    return anomalies

def build_gemini_prompt(current_data):
    """Generate a context-aware Gemini prompt using current data and historical trends."""
    profile = get_profile()
    history = load_history()[-5:]  # last 5 runs for context
    prompt = f"""
    Device Security Contextual Analysis

    Current Data:
    {json.dumps(current_data, indent=2)}

    Historical Profile:
    {json.dumps(profile, indent=2)}

    Recent History (Last 5 runs):
    {json.dumps(history, indent=2)}

    Using both current and past behavior, provide:
    - Updated risk grade and reasoning
    - Insights comparing past and current patterns
    - Adaptive recommendations based on long-term risk trends
    - If possible, predictive statement: \"If X improved, score would be approximately Y\"
    """
    return prompt

def show_trend():
    """Print a simple ASCII trend line for past risk scores."""
    history = load_history()
    if not history:
        print("No scan history found.")
        return
    print("\n📊 Risk Score Trend Over Time:")
    for i, h in enumerate(history):
        score = h.get("score", 0)
        timestamp = h.get("timestamp", f"Run {i+1}")
        bar = "#" * int(score / 2)
        print(f"{timestamp:20} | {score:5.1f} | {bar}")
