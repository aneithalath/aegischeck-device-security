import os
import json
import datetime
import math
from collections import Counter, defaultdict
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.ensemble import RandomForestRegressor
from sklearn.exceptions import NotFittedError
import threading
from typing import List, Dict, Any, Tuple

HISTORY_PATH = os.path.join(os.path.dirname(__file__), '../../data/risk_history.json')
EMBEDDINGS_PATH = os.path.join(os.path.dirname(__file__), '../../data/risk_embeddings.json')
HISTORY_MAX = 100
CATEGORY_KEYWORDS = [
    # Example: ('password', ['password', 'credential', 'login']),
    ('password', ['password', 'credential', 'login']),
    ('os', ['os', 'system', 'patch', 'update']),
    ('permissions', ['permission', 'access', 'startup']),
    ('mfa', ['mfa', 'multi-factor', '2fa']),
    ('network', ['network', 'wifi', 'ssid']),
    ('browser', ['browser', 'extension', 'web']),
]
_embed_lock = threading.Lock()
_model = None
def get_embedding_model():
    global _model
    if _model is None:
        with _embed_lock:
            if _model is None:
                _model = SentenceTransformer('all-MiniLM-L6-v2')
    return _model

def compute_embedding(text: str) -> list:
    model = get_embedding_model()
    emb = model.encode([text], show_progress_bar=False)
    return emb[0].tolist()

def save_embeddings(embeddings: list):
    os.makedirs(os.path.dirname(EMBEDDINGS_PATH), exist_ok=True)
    with open(EMBEDDINGS_PATH, 'w', encoding='utf-8') as f:
        json.dump(embeddings, f, indent=2)

def load_embeddings() -> list:
    if not os.path.exists(EMBEDDINGS_PATH):
        return []
    try:
        with open(EMBEDDINGS_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []

def update_embeddings():
    """Ensure embeddings are up to date for all history entries."""
    history = load_history()
    embeddings = []
    model = get_embedding_model()
    for entry in history:
        text = '\n'.join(entry.get('insights', []) + entry.get('recommendations', []))
        emb = model.encode([text], show_progress_bar=False)[0].tolist()
        meta = {
            'timestamp': entry.get('timestamp'),
            'score': entry.get('score'),
            'grade': entry.get('grade'),
            'embedding': emb,
            'insights': entry.get('insights', []),
            'recommendations': entry.get('recommendations', []),
            'summary': text[:200]
        }
        embeddings.append(meta)
    save_embeddings(embeddings)
    return embeddings

def cosine_similarity(a, b):
    a = np.array(a)
    b = np.array(b)
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-8))

def get_similar_risks(current_embedding, top_k=3) -> list:
    """Returns summaries of top_k most similar past risks."""
    embeddings = load_embeddings()
    if not embeddings:
        return []
    sims = []
    for entry in embeddings:
        sim = cosine_similarity(current_embedding, entry['embedding'])
        sims.append((sim, entry))
    sims.sort(reverse=True, key=lambda x: x[0])
    return [e['summary'] for _, e in sims[:top_k]]
def summarize_risk_history(limit=5):
    """Summarize recent risk history for prompt context."""
    history = load_history()[-limit:]
    if not history:
        return "No historical data available."
    lines = []
    for h in history:
        t = h.get('timestamp', '')
        g = h.get('grade', '')
        s = h.get('score', '')
        cats = ', '.join(h.get('categories', {}).keys()) if h.get('categories') else ''
        lines.append(f"[{t[:10]}] Grade: {g}, Score: {s}, Categories: {cats}")
    return '\n'.join(lines)

def determine_focus_topic():
    """Determine the main focus topic for this session based on recent history."""
    history = load_history()
    if not history:
        return "General security hygiene"
    cat_summary = summarize_categories(history)
    if not cat_summary:
        return "General security hygiene"
    focus = max(cat_summary.items(), key=lambda x: x[1])[0]
    focus_map = {
        'password': 'password hygiene',
        'os': 'system patching',
        'permissions': 'permissions management',
        'startup': 'startup program review',
        'mfa': 'multi-factor authentication',
        'patch': 'system patching',
        'network': 'network security',
        'browser': 'browser security',
    }
    return focus_map.get(focus, focus)

def get_adaptive_prompt_context():
    """Return focus and context summary for adaptive prompt engineering."""
    focus = determine_focus_topic()
    context = summarize_risk_history(limit=5)
    return {"focus": focus, "context": context}

# --- Adaptive Prompt Engineering ---
def get_adaptive_prompt_context(history, sanitized):
    """Return focus and context summary for adaptive prompt engineering, using history and current scan."""
    # Use the most recent history and current scan to determine focus
    focus = determine_focus_topic()
    context = summarize_risk_history(limit=5)
    # Optionally, add more context from sanitized input
    return {"focus": focus, "context": context, "current": sanitized}

# --- Gemini Prompt Composer ---
def compose_gemini_prompt(contextual_payload, adaptive_context):
    """Compose a prompt string for Gemini using context and adaptive focus."""
    prompt = (
        "You are a cybersecurity intelligence model. Analyze the current and historical device risk data, correlate patterns, and provide trend-aware insights and predictive advice.\n"
        f"Current and historical risk data (JSON):\n{json.dumps(contextual_payload, indent=2)}\n"
        f"Adaptive context: {json.dumps(adaptive_context, indent=2)}\n"
        "Instructions:\n"
        "- Provide 2–5 insights linking multiple risk vectors (e.g., how OS risk and password risk interact).\n"
        "- Provide 2–5 actionable recommendations.\n"
        "- Provide 1–2 predictive suggestions (e.g., 'If passwords were all secure, risk would drop to X').\n"
        "- Respond exactly in JSON with the keys: 'score' (0-100), 'grade' (Low/Medium/High/Critical), 'insights' (2-5 strings), 'recommendations' (2-5 strings), 'predictive' (1-2 strings).\n"
        "- Do NOT include any personal info, passwords, URLs, or Wi-Fi SSIDs.\n"
        "- If history is present, highlight trends (improving, declining, stable).\n"
        "- If parsing fails, fallback to local analysis.\n"
    )
    return prompt

# --- Offline Predictive Modeling ---
def train_offline_predictor():
    """Train a RandomForestRegressor on history if enough data."""
    history = load_history()
    if len(history) < 5:
        return None, False
    X = []
    y = []
    for h in history:
        try:
            X.append([
                float(h.get('pw_compromised', 0)),
                float(h.get('perm_risk_count', 0)),
                float(h.get('score', 0)),
            ])
            y.append(float(h.get('score', 0)))
        except Exception:
            continue
    if len(X) < 5:
        return None, False
    model = RandomForestRegressor(n_estimators=20, random_state=42)
    model.fit(X, y)
    return model, True

def predict_next_risk(model=None):
    """Predict the next risk score and commentary."""
    history = load_history()
    if len(history) < 5:
        return {
            "score": None,
            "commentary": "Insufficient historical data for prediction.",
            "source": "hardcoded_fallback"
        }
    if model is None:
        model, ok = train_offline_predictor()
        if not ok:
            return {
                "score": None,
                "commentary": "Insufficient historical data for prediction.",
                "source": "hardcoded_fallback"
            }
    last = history[-1]
    X_pred = [[
        float(last.get('pw_compromised', 0)),
        float(last.get('perm_risk_count', 0)),
        float(last.get('score', 0)),
    ]]
    try:
        pred = float(model.predict(X_pred)[0])
        commentary = f"Projected score may {'drop' if pred < X_pred[0][2] else 'rise'} from {X_pred[0][2]:.0f} → {pred:.0f} next scan."
        return {
            "score": round(pred, 2),
            "commentary": commentary,
            "source": "offline_predictor"
        }
    except Exception:
        return {
            "score": None,
            "commentary": "Prediction failed.",
            "source": "hardcoded_fallback"
        }

# --- Offline Predictor for Fallback Chain ---
def predict_next_risk(history=None, sanitized=None, model=None):
    """Predict the next risk score and generate fallback insights/recommendations."""
    if history is None:
        history = load_history()
    if sanitized is None:
        sanitized = {}
    if len(history) < 5:
        return None
    if model is None:
        model, ok = train_offline_predictor()
        if not ok:
            return None
    last = history[-1]
    X_pred = [[
        float(last.get('pw_compromised', 0)),
        float(last.get('perm_risk_count', 0)),
        float(last.get('score', 0)),
    ]]
    try:
        pred = float(model.predict(X_pred)[0])
        # Simple logic for grade
        if pred >= 70:
            grade = "Critical"
        elif pred >= 50:
            grade = "High"
        elif pred >= 25:
            grade = "Medium"
        else:
            grade = "Low"
        insights = [
            f"Predicted next risk score: {pred:.1f} (current: {X_pred[0][2]:.1f})",
            f"Password risk: {sanitized.get('pw_compromised', 'N/A')} compromised.",
            f"Permission risk: {sanitized.get('perm_risk_count', 'N/A')} high/critical."
        ]
        recommendations = [
            "Reduce compromised passwords and high-risk permissions to lower future risk.",
            "Continue regular updates and security reviews."
        ]
        predictive = [
            f"If all passwords were secure, risk would drop to ~{max(0, pred-20):.1f}.",
            f"If permissions were all safe, risk would drop to ~{max(0, pred-10):.1f}."
        ]
        return {
            "score": round(pred, 2),
            "grade": grade,
            "insights": insights,
            "recommendations": recommendations,
            "predictive": predictive
        }
    except Exception:
        return None

def load_history() -> List[Dict[str, Any]]:
    """Safely load risk history from JSON file."""
    if not os.path.exists(HISTORY_PATH):
        return []
    try:
        with open(HISTORY_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []

def save_history(history: List[Dict[str, Any]]):
    """Save risk history to file, pruning to HISTORY_MAX entries."""
    os.makedirs(os.path.dirname(HISTORY_PATH), exist_ok=True)
    history = history[-HISTORY_MAX:]
    with open(HISTORY_PATH, 'w', encoding='utf-8') as f:
        json.dump(history, f, indent=2)

def append_and_prune(entry: Dict[str, Any]):
    """Append a new entry and prune history to HISTORY_MAX."""
    history = load_history()
    # Ensure timestamp is present and ISO8601
    if 'timestamp' not in entry:
        entry['timestamp'] = datetime.datetime.now().isoformat()
    else:
        # Try to reformat if not ISO
        try:
            dt = datetime.datetime.fromisoformat(entry['timestamp'])
            entry['timestamp'] = dt.isoformat()
        except Exception:
            entry['timestamp'] = datetime.datetime.now().isoformat()
    history.append(entry)
    save_history(history)

def parse_categories(insights: List[str]) -> Dict[str, int]:
    """Extract category counts from a list of insights."""
    cat_counts = Counter()
    for insight in insights:
        lower = insight.lower()
        for cat, keywords in CATEGORY_KEYWORDS:
            if any(kw in lower for kw in keywords):
                cat_counts[cat] += 1
    return dict(cat_counts)

def summarize_categories(history: List[Dict[str, Any]]) -> Dict[str, int]:
    """Summarize category frequencies across all history."""
    total = Counter()
    for entry in history:
        entry_cats = entry.get('categories')
        if not entry_cats:
            entry_cats = parse_categories(entry.get('insights', []))
        total.update(entry_cats)
    return dict(total)

def weighted_trend(history: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate weighted average score and trend using timestamp and index decay."""
    if not history:
        return {"weighted_score": None, "trend": "stable", "raw_scores": []}
    now = datetime.datetime.now()
    weighted_sum = 0.0
    total_weight = 0.0
    scores = []
    for idx, entry in enumerate(history):
        score = entry.get('score')
        if not isinstance(score, (int, float)):
            continue
        scores.append(score)
        # Time decay: half-life of 14 days
        try:
            ts = entry.get('timestamp')
            dt = datetime.datetime.fromisoformat(ts)
            days_ago = (now - dt).total_seconds() / 86400.0
        except Exception:
            days_ago = idx  # fallback: use index as proxy
        time_decay = 0.5 ** (days_ago / 14.0)
        # Index decay: more recent = higher weight
        index_decay = 0.9 ** (len(history) - idx - 1)
        weight = time_decay * index_decay
        weighted_sum += score * weight
        total_weight += weight
    weighted_score = weighted_sum / total_weight if total_weight > 0 else None
    # Trend: compare weighted average of first half vs second half
    n = len(scores)
    if n < 2:
        trend = "stable"
    else:
        mid = n // 2
        first = scores[:mid]
        second = scores[mid:]
        avg_first = sum(first) / len(first) if first else 0
        avg_second = sum(second) / len(second) if second else 0
        if avg_second > avg_first + 2:
            trend = "improving"
        elif avg_second < avg_first - 2:
            trend = "declining"
        else:
            trend = "stable"
    return {"weighted_score": round(weighted_score, 2) if weighted_score is not None else None, "trend": trend, "raw_scores": scores}

def enrich_entry_with_categories(entry: Dict[str, Any]):
    """Add a 'categories' field to the entry based on its insights."""
    entry['categories'] = parse_categories(entry.get('insights', []))
    return entry

# Integration helpers for risk_analyzer and main

def get_history_and_trends() -> Tuple[List[Dict[str, Any]], Dict[str, int], Dict[str, Any]]:
    """Load history, summarize categories, and compute weighted trend."""
    history = load_history()
    cat_summary = summarize_categories(history)
    trend_info = weighted_trend(history)
    return history, cat_summary, trend_info
