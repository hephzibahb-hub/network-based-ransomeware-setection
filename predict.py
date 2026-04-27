import pandas as pd
import numpy as np
import joblib
import io
from collections import Counter, defaultdict
from pathlib import Path

from src.inference.zeek_runner import run_zeek_on_pcap

# -----------------------------
# Paths
# -----------------------------
MODEL_PATH = "data/models/ransomware_detector_final.pkl"
ENCODER_PATH = "data/models/label_encoder_final.pkl"

# -----------------------------
# Load model + encoder ONCE
# -----------------------------
model = joblib.load(MODEL_PATH)
label_encoder = joblib.load(ENCODER_PATH)

# Reduce CPU noise
try:
    model.named_steps["model"].n_jobs = 1
except Exception:
    pass

# -----------------------------
# Training schema (FROZEN)
# -----------------------------
FEATURE_COLUMNS = [
    "ts", "uid", "id.orig_h", "id.orig_p",
    "id.resp_h", "id.resp_p", "proto", "service",
    "duration", "orig_bytes", "resp_bytes",
    "conn_state", "local_orig", "local_resp",
    "missed_bytes", "history", "orig_pkts",
    "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
    "tunnel_parents", "ip_proto"
]

NUMERIC_COLS = [
    "ts", "id.orig_p", "id.resp_p", "duration",
    "orig_bytes", "resp_bytes", "missed_bytes",
    "orig_pkts", "orig_ip_bytes", "resp_pkts",
    "resp_ip_bytes", "ip_proto"
]

# -----------------------------
# Zeek conn.log loader
# -----------------------------
def load_connlog_from_bytes(file_bytes: bytes) -> pd.DataFrame:
    text = file_bytes.decode("utf-8", errors="ignore")
    buffer = io.StringIO(text)

    df = pd.read_csv(
        buffer,
        sep="\t",
        comment="#",
        header=None,
        low_memory=False
    )

    if df.empty:
        return df

    # Assign known columns
    df.columns = FEATURE_COLUMNS[:len(df.columns)]

    # Ensure all required columns exist
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0

    # Enforce dtypes
    for col in NUMERIC_COLS:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    for col in FEATURE_COLUMNS:
        if col not in NUMERIC_COLS:
            df[col] = df[col].astype(str)

    return df[FEATURE_COLUMNS]

# -----------------------------
# Confidence aggregation helper
# -----------------------------
def aggregate_confidence(probas, labels):
    """
    Returns:
    - mean confidence per family
    - max confidence per family
    """
    family_scores = defaultdict(list)

    for row_probs, label in zip(probas, labels):
        family_scores[label].append(max(row_probs))

    return {
        fam: {
            "mean_confidence": round(float(np.mean(scores)), 4),
            "max_confidence": round(float(np.max(scores)), 4)
        }
        for fam, scores in family_scores.items()
    }

# -----------------------------
# Interpretability helpers (Step 3A)
# -----------------------------
def confidence_tier(mean_confidence: float, dominance_ratio: float) -> str:
    if dominance_ratio >= 0.9 and mean_confidence >= 0.9:
        return "High"
    if dominance_ratio >= 0.6 and mean_confidence >= 0.7:
        return "Medium"
    return "Low"


def build_explanation(dominant_family: str, dominance_ratio: float, tier: str) -> str:
    percent = round(dominance_ratio * 100, 2)

    if dominant_family == "Benign":
        return (
            "The analyzed traffic appears benign with no significant "
            "malicious patterns detected."
        )

    return (
        f"The analyzed traffic is {tier.lower()} confidence "
        f"{dominant_family} ransomware activity. "
        f"Approximately {percent}% of observed network flows "
        f"match known {dominant_family} behavior."
    )

# -----------------------------
# MAIN inference contract
# -----------------------------
def predict_connlog_bytes(file_bytes: bytes) -> dict:
    """
    Inference contract (EXTENDED, NOT BROKEN)

    Input:
        conn.log bytes

    Output:
        {
          total_rows,
          benign_rows,
          malicious_rows,
          malware_ratio,
          summary,
          dominant_family,
          confidence,
          confidence_tier,
          explanation,
          verdict
        }
    """

    df = load_connlog_from_bytes(file_bytes)

    if df.empty:
        return {"error": "No valid conn.log rows found."}

    # Row-level prediction
    preds = model.predict(df)
    labels = label_encoder.inverse_transform(preds)

    # Optional confidence
    probas = None
    if hasattr(model, "predict_proba"):
        probas = model.predict_proba(df)

    counts = Counter(labels)

    total = len(labels)
    benign = counts.get("Benign", 0)
    malicious = total - benign
    malware_ratio = round(malicious / total, 4)

    # Dominant non-benign family
    dominant_family = "Benign"
    if malicious > 0:
        dominant_family = max(
            ((fam, cnt) for fam, cnt in counts.items() if fam != "Benign"),
            key=lambda x: x[1]
        )[0]

    # Confidence aggregation
    confidence = {}
    if probas is not None:
        confidence = aggregate_confidence(probas, labels)

    # Interpretability
    dominant_count = counts.get(dominant_family, 0)
    dominance_ratio = dominant_count / total if total > 0 else 0

    mean_conf = 0.0
    if dominant_family in confidence:
        mean_conf = confidence[dominant_family]["mean_confidence"]

    tier = confidence_tier(mean_conf, dominance_ratio)
    explanation = build_explanation(dominant_family, dominance_ratio, tier)

    verdict = "Benign" if malicious == 0 else "Malware Detected"

    return {
        "total_rows": total,
        "benign_rows": benign,
        "malicious_rows": malicious,
        "malware_ratio": malware_ratio,
        "summary": dict(counts),
        "dominant_family": dominant_family,
        "confidence": confidence,
        "confidence_tier": tier,
        "explanation": explanation,
        "verdict": verdict
    }

# -----------------------------
# PCAP → Zeek → inference
# -----------------------------
def predict_pcap_file(pcap_path: str) -> dict:
    """
    End-to-end prediction for a PCAP file.

    Pipeline:
        PCAP → Zeek → conn.log → model inference
    """

    pcap_path = Path(pcap_path).resolve()

    if not pcap_path.exists():
        return {"error": f"PCAP file not found: {pcap_path}"}

    # Run Zeek via WSL
    conn_log_path = run_zeek_on_pcap(str(pcap_path))

    # Read generated conn.log
    with open(conn_log_path, "rb") as f:
        conn_bytes = f.read()

    return predict_connlog_bytes(conn_bytes)
