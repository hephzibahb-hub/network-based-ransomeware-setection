
import pandas as pd
import numpy as np
import joblib
import io
from collections import Counter, defaultdict
from pathlib import Path

# Lazy-load TensorFlow to avoid slowing down the RF pipeline at startup
import tensorflow as tf

from src.inference.zeek_runner import run_zeek_on_pcap

# ---------------------------------
# Paths  (model lives in data/data/models/)
# ---------------------------------
DL_MODEL_PATH      = "data/dl_models/ransomware_dl_model.h5"
DL_PREPROCESSOR    = "data/dl_models/dl_preprocessor.pkl"
DL_LABEL_ENCODER   = "data/dl_models/dl_label_encoder.pkl"

print("[DL] Loading DL model and preprocessors…")
_DL_LOAD_ERROR = None
try:
    dl_model         = tf.keras.models.load_model(DL_MODEL_PATH)
    dl_preprocessor  = joblib.load(DL_PREPROCESSOR)
    dl_label_encoder = joblib.load(DL_LABEL_ENCODER)
    print("[DL] DL model ready.")
except Exception as _e:
    _DL_LOAD_ERROR = str(_e)
    dl_model = dl_preprocessor = dl_label_encoder = None
    print(f"[DL] WARNING: DL model failed to load — {_DL_LOAD_ERROR}")
    print("[DL] DL endpoints will return an error. RF endpoints are unaffected.")

# ---------------------------------
# Feature schema must match training
# ---------------------------------
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

# ---------------------------------
# Zeek conn.log loader (same as RF)
# ---------------------------------
def _load_connlog(file_bytes: bytes) -> pd.DataFrame:
    text   = file_bytes.decode("utf-8", errors="ignore")
    buffer = io.StringIO(text)

    df = pd.read_csv(buffer, sep="\t", comment="#", header=None, low_memory=False)

    if df.empty:
        return df

    df.columns = FEATURE_COLUMNS[:len(df.columns)]

    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0

    for col in NUMERIC_COLS:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    for col in FEATURE_COLUMNS:
        if col not in NUMERIC_COLS:
            df[col] = df[col].astype(str)

    return df[FEATURE_COLUMNS]


# ---------------------------------
# Confidence helpers
# ---------------------------------
def _aggregate_confidence(probas, labels):
    family_scores = defaultdict(list)
    for row_probs, label in zip(probas, labels):
        family_scores[label].append(float(np.max(row_probs)))
    return {
        fam: {
            "mean_confidence": round(float(np.mean(scores)), 4),
            "max_confidence":  round(float(np.max(scores)), 4),
        }
        for fam, scores in family_scores.items()
    }


def _confidence_tier(mean_conf: float, dominance_ratio: float) -> str:
    if dominance_ratio >= 0.9 and mean_conf >= 0.9:
        return "High"
    if dominance_ratio >= 0.6 and mean_conf >= 0.7:
        return "Medium"
    return "Low"


def _build_explanation(dominant_family: str, dominance_ratio: float, tier: str) -> str:
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


# ---------------------------------
# Main DL inference  (conn.log bytes)
# ---------------------------------
def predict_dl_connlog_bytes(file_bytes: bytes) -> dict:
    """
    Identical response schema to predict_connlog_bytes() in predict.py
    so the frontend can use either endpoint interchangeably.
    """
    if _DL_LOAD_ERROR:
        return {"error": f"DL model unavailable: {_DL_LOAD_ERROR}"}

    df = _load_connlog(file_bytes)

    if df.empty:
        return {"error": "No valid conn.log rows found."}

    # Apply the same preprocessing the DL model was trained with
    X = dl_preprocessor.transform(df)

    # Raw softmax probabilities  [n_rows, n_classes]
    probas = dl_model.predict(X, verbose=0)

    # Convert to class indices then to family names
    pred_indices = np.argmax(probas, axis=1)
    labels       = dl_label_encoder.inverse_transform(pred_indices)

    counts    = Counter(labels)
    total     = len(labels)
    benign    = counts.get("Benign", 0)
    malicious = total - benign

    malware_ratio = round(malicious / total, 4) if total > 0 else 0.0

    # Dominant non-benign family
    dominant_family = "Benign"
    if malicious > 0:
        dominant_family = max(
            ((fam, cnt) for fam, cnt in counts.items() if fam != "Benign"),
            key=lambda x: x[1]
        )[0]

    confidence       = _aggregate_confidence(probas, labels)
    dominant_count   = counts.get(dominant_family, 0)
    dominance_ratio  = dominant_count / total if total > 0 else 0.0
    mean_conf        = confidence.get(dominant_family, {}).get("mean_confidence", 0.0)

    tier        = _confidence_tier(mean_conf, dominance_ratio)
    explanation = _build_explanation(dominant_family, dominance_ratio, tier)
    verdict     = "Benign" if malicious == 0 else "Malware Detected"

    return {
        "total_rows":       total,
        "benign_rows":      benign,
        "malicious_rows":   malicious,
        "malware_ratio":    malware_ratio,
        "summary":          dict(counts),
        "dominant_family":  dominant_family,
        "confidence":       confidence,
        "confidence_tier":  tier,
        "explanation":      explanation,
        "verdict":          verdict,
        "model_used":       "Deep Learning (TensorFlow)",
    }


# ---------------------------------
# PCAP → Zeek → DL inference
# ---------------------------------
def predict_dl_pcap_file(pcap_path: str) -> dict:
    if _DL_LOAD_ERROR:
        return {"error": f"DL model unavailable: {_DL_LOAD_ERROR}"}

    pcap_path = Path(pcap_path).resolve()
    if not pcap_path.exists():
        return {"error": f"PCAP file not found: {pcap_path}"}

    conn_log_path = run_zeek_on_pcap(str(pcap_path))
    with open(conn_log_path, "rb") as f:
        conn_bytes = f.read()

    return predict_dl_connlog_bytes(conn_bytes)
