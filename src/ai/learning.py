import os
import json
import datetime
import math
from collections import Counter, defaultdict
from typing import List, Dict, Any, Tuple

HISTORY_PATH = os.path.join(os.path.dirname(__file__), '../../data/risk_history.json')
HISTORY_MAX = 100
CATEGORY_KEYWORDS = [
    ("password", ["password", "credential", "compromised", "breach", "mfa", "account"]),
    ("os", ["os", "patch", "update", "vulnerab", "windows", "system"]),
    ("permissions", ["permission", "consent", "access", "privilege", "admin"]),
    ("startup", ["startup", "autostart", "boot", "autorun"]),
    ("mfa", ["mfa", "multi-factor", "2fa"]),
    ("patch", ["patch", "update", "fix"]),
    ("network", ["network", "wifi", "ssid", "connection"]),
    ("browser", ["browser", "chrome", "firefox", "edge", "safari"]),
]

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
