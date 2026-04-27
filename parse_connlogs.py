import pandas as pd
import os
import glob

BASE = "malicious"
ROWS = []

print("[+] Scanning families...")

for family in os.listdir(BASE):
    fam_dir = os.path.join(BASE, family)
    if not os.path.isdir(fam_dir):
        continue

    print(" ->", family)

    conn_logs = glob.glob(f"{fam_dir}/**/conn.log", recursive=True)

    for log in conn_logs:
        try:
            df = pd.read_csv(
                log,
                sep="\t",
                comment="#",
                engine="python",
                on_bad_lines="skip"
            )
            df["family"] = family
            ROWS.append(df)
        except Exception as e:
            print(f"   [!] Failed to parse {log}: {e}")

print("\n[+] Concatenating...")

final = pd.concat(ROWS, ignore_index=True)

print("[+] Saving clean file as clean_conn.csv")
final.to_csv("clean_conn.csv", index=False)

print("[+] Done.")
