import pandas as pd
import numpy as np

print("[+] Loading final_dataset.csv ...")
df = pd.read_csv("final_dataset.csv")

print("[+] Dropping useless 'family' column...")
df = df.drop(columns=["family"])

# Columns that must be numeric
numeric_fix = ["duration", "orig_bytes", "resp_bytes"]

print("[+] Fixing numeric columns...")
for col in numeric_fix:
    df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)

print("[+] Saving cleaned dataset as final_dataset_clean.csv ...")
df.to_csv("final_dataset_clean.csv", index=False)

print("[+] Done. Ready for training.")
