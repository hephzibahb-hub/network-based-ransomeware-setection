import pandas as pd
import numpy as np
import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, StandardScaler, LabelEncoder
from sklearn.compose import ColumnTransformer
from sklearn.utils.class_weight import compute_class_weight
import joblib
import os

# ---------------------------------
# Paths
# ---------------------------------
DATA_PATH = "data/raw/final_dataset_clean.csv"
MODEL_SAVE_PATH = "data/models/ransomware_dl_model.h5"

print("[+] Loading dataset...")
df = pd.read_csv(DATA_PATH)

# ---------------------------------
# Split features & label
# ---------------------------------
X = df.drop(columns=["label"])
y = df["label"]

label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

num_classes = len(np.unique(y_encoded))

# ---------------------------------
# Detect numeric & categorical
# ---------------------------------
numeric_cols = X.select_dtypes(include=["int64", "float64"]).columns.tolist()
categorical_cols = X.select_dtypes(include=["object"]).columns.tolist()

# ---------------------------------
# Preprocessing
# ---------------------------------
print("[+] Preprocessing...")

preprocessor = ColumnTransformer([
    ("num", StandardScaler(), numeric_cols),
    ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_cols)
])

X_processed = preprocessor.fit_transform(X)

# ---------------------------------
# Train / Test Split
# ---------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X_processed,
    y_encoded,
    test_size=0.2,
    random_state=42,
    stratify=y_encoded
)

# ---------------------------------
# Handle class imbalance
# ---------------------------------
class_weights = compute_class_weight(
    class_weight="balanced",
    classes=np.unique(y_train),
    y=y_train
)

class_weight_dict = dict(enumerate(class_weights))

# ---------------------------------
# Build Model
# ---------------------------------
print("[+] Building Deep Learning model...")

model = tf.keras.Sequential([
    tf.keras.layers.Dense(512, activation="relu", input_shape=(X_train.shape[1],)),
    tf.keras.layers.Dropout(0.3),

    tf.keras.layers.Dense(256, activation="relu"),
    tf.keras.layers.Dropout(0.3),

    tf.keras.layers.Dense(128, activation="relu"),

    tf.keras.layers.Dense(num_classes, activation="softmax")
])

model.compile(
    optimizer="adam",
    loss="sparse_categorical_crossentropy",
    metrics=["accuracy"]
)

# ---------------------------------
# Callbacks (THIS SAVES YOUR LIFE)
# ---------------------------------
callbacks = [
    tf.keras.callbacks.EarlyStopping(
        patience=3,
        restore_best_weights=True
    )
]

# ---------------------------------
# Train
# ---------------------------------
print("[+] Training...")

history = model.fit(
    X_train,
    y_train,
    validation_data=(X_test, y_test),
    epochs=15,              # Reduced from 20
    batch_size=1024,
    class_weight=class_weight_dict,
    callbacks=callbacks,
    verbose=1
)

# ---------------------------------
# Evaluate
# ---------------------------------
loss, accuracy = model.evaluate(X_test, y_test)
print(f"\n[+] DL Model Accuracy: {accuracy*100:.2f}%")

# ---------------------------------
# Save model + preprocessors
# ---------------------------------
os.makedirs("data/models", exist_ok=True)

model.save(MODEL_SAVE_PATH)
joblib.dump(preprocessor, "data/models/dl_preprocessor.pkl")
joblib.dump(label_encoder, "data/models/dl_label_encoder.pkl")

print("[+] Deep Learning model saved successfully.")