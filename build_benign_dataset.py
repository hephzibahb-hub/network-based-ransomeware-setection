import os
import pandas as pd

ROOT = "benign/logs"

def parse_connlog(path):
    df = []
    fields = None
    sep = "\t"

    with open(path, "r", errors="ignore") as f:
        for line in f:
            if line.startswith("#separator"):
                raw = line.split()[-1]
                sep = raw.encode().decode("unicode_escape")

            if line.startswith("#fields"):
                parts = line.strip().split()
                fields = parts[1:]  # keep ts..fields
                continue

            if line.startswith("#"):
                continue

            parts = line.strip().split(sep)

            if fields and len(parts) == len(fields):
                df.append(parts)

    return pd.DataFrame(df, columns=fields)


all_frames = []

print("[+] Scanning benign conn logs...")

for root, dirs, files in os.walk(ROOT):
    for f in files:
        if f == "conn.log":
            full = os.path.join(root, f)
            print(" ->", full)
            df = parse_connlog(full)
            df["family"] = "Benign"
            all_frames.append(df)

print("[+] Combining benign data...")
benign_df = pd.concat(all_frames, ignore_index=True)

print("[+] Saving benign_conn_dataset.csv")
benign_df.to_csv("benign_conn_dataset.csv", index=False)

print("[+] Done. Rows:", len(benign_df))
