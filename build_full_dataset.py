import pandas as pd

print("[+] Loading malicious dataset...")
mal_X = pd.read_csv("X_clean.csv")
mal_y = pd.read_csv("y_merged.csv")["family"]
mal = mal_X.copy()
mal["label"] = mal_y

print("[+] Loading benign dataset...")
benign = pd.read_csv("benign/benign_conn_dataset.csv")
benign["label"] = "Benign"

print("[+] Combining...")
full = pd.concat([mal, benign], ignore_index=True)

print("[+] Shuffling...")
full = full.sample(frac=1, random_state=42).reset_index(drop=True)

print("[+] Saving final_dataset.csv ...")
full.to_csv("final_dataset.csv", index=False)

print("[+] Done. Total rows:", len(full))
print(full["label"].value_counts())
