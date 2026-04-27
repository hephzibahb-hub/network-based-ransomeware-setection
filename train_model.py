import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.utils.class_weight import compute_class_weight
import matplotlib.pyplot as plt
import seaborn as sns

# Load data
print("[+] Loading dataset...")
X = pd.read_csv("X_clean.csv")
y = pd.read_csv("y_merged.csv")["family"]

# Encode target
label_encoder = LabelEncoder()
y_enc = label_encoder.fit_transform(y)

# Identify columns
categorical_cols = [
    "uid","id.orig_h","id.resp_h","proto","service",
    "conn_state","local_orig","local_resp","history",
    "tunnel_parents"
]

numeric_cols = [
    "ts","id.orig_p","id.resp_p","duration",
    "orig_bytes","resp_bytes",
    "missed_bytes","orig_pkts","orig_ip_bytes",
    "resp_pkts","resp_ip_bytes","ip_proto"
]

# Preprocessor
preprocessor = ColumnTransformer(
    transformers=[
        ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=True), categorical_cols),
        ("num", "passthrough", numeric_cols),
    ]
)

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y_enc, test_size=0.10, stratify=y_enc, random_state=42
)

# Compute class weights
classes = np.unique(y_enc)
weights = compute_class_weight(class_weight="balanced", classes=classes, y=y_enc)
class_weights = {cls: w for cls, w in zip(classes, weights)}

# Model
rf = RandomForestClassifier(
    n_estimators=300,
    max_depth=None,
    n_jobs=-1,
    class_weight=class_weights,
    verbose=2
)

pipeline = Pipeline([
    ("prep", preprocessor),
    ("model", rf)
])

# Train
print("[+] Training model...")
pipeline.fit(X_train, y_train)

print("[+] Evaluating...")
preds = pipeline.predict(X_test)

print(f"Accuracy: {accuracy_score(y_test, preds)*100:.2f}%")
print(classification_report(
    y_test, preds,
    target_names=label_encoder.classes_
))

# Save model
joblib.dump(pipeline, "ransomware_detector_final.pkl")
joblib.dump(label_encoder, "label_encoder_final.pkl")
print("[+] Model saved successfully.")
