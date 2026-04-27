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
from sklearn.utils.multiclass import unique_labels

# ============================================================
# 1) Load cleaned dataset
# ============================================================
print("[+] Loading cleaned dataset...")
df = pd.read_csv("final_dataset_clean.csv")

X = df.drop(columns=["label"])
y = df["label"]

# ============================================================
# 2) Encode labels
# ============================================================
print("[+] Encoding labels...")
label_encoder = LabelEncoder()
y_enc = label_encoder.fit_transform(y)

print("Classes:", list(label_encoder.classes_))
print("Total classes:", len(label_encoder.classes_))

# ============================================================
# 3) Column categories
# ============================================================
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

preprocessor = ColumnTransformer(
    transformers=[
        ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=True), categorical_cols),
        ("num", "passthrough", numeric_cols)
    ]
)

# ============================================================
# 4) Train/test split (stratified!)
# ============================================================
print("[+] Splitting dataset...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y_enc,
    test_size=0.10,
    stratify=y_enc,
    random_state=42
)

print("Train samples:", len(X_train))
print("Test samples: ", len(X_test))

# ============================================================
# 5) Compute class weights
# ============================================================
print("[+] Computing class weights...")

classes = np.unique(y_enc)
weights = compute_class_weight(
    class_weight="balanced",
    classes=classes,
    y=y_enc
)

class_weights = {cls: w for cls, w in zip(classes, weights)}

print("Class weights generated.")

# ============================================================
# 6) Build model
# ============================================================
rf = RandomForestClassifier(
    n_estimators=300,
    max_depth=None,
    n_jobs=-1,
    class_weight=class_weights,
    verbose=2
)

pipeline = Pipeline([
    ("preprocessor", preprocessor),
    ("model", rf)
])

# ============================================================
# 7) Train
# ============================================================
print("[+] Training model...")
pipeline.fit(X_train, y_train)

# ============================================================
# 8) Evaluate
# ============================================================
print("[+] Evaluating...")
preds = pipeline.predict(X_test)

acc = accuracy_score(y_test, preds)
print(f"\n[+] Accuracy: {acc*100:.2f}%\n")

valid_labels = unique_labels(y_test, preds)
valid_target_names = label_encoder.inverse_transform(valid_labels)

print("========== CLASSIFICATION REPORT ==========\n")
print(classification_report(
    y_test, preds,
    labels=valid_labels,
    target_names=valid_target_names
))

# ============================================================
# 9) Save model
# ============================================================
print("[+] Saving model + encoder...")
joblib.dump(pipeline, "ransomware_detector_v2.pkl")
joblib.dump(label_encoder, "label_encoder_v2.pkl")

print("[+] Training complete. Model saved.")
