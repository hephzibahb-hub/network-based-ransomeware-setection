import os
import pandas as pd

ROOT = "malicious"

OUTPUT = []

def load_conn_log(path, family):
    try:
        df = pd.read_csv(
            path,
            sep="\t",
            comment="#",
            header=None,
            on_bad_lines="skip",
            engine="python"
        )
        # Assign proper columns
        df.columns = [
            "ts", "uid", "id.orig_h", "id.orig_p",
            "id.resp_h", "id.resp_p", "proto", "service",
            "duration", "orig_bytes", "resp_bytes", "conn_state",
            "local_orig", "local_resp", "missed_bytes",
            "history", "orig_pkts", "orig_ip_bytes",
            "resp_pkts", "resp_ip_bytes", "tunnel_parents", "ip_proto"
        ]

        df["family"] = family
        RETURN = df
        return RETURN

    except Exception as e:
        print(f"[!] Failed to read {path}: {e}")
        return None


print("[+] Scanning ransomware families...")

for family in sorted(os.listdir(ROOT)):
    fam_dir = os.path.join(ROOT, family)
    if not os.path.isdir(fam_dir):
        continue

    print(f" -> {family}")

    for root, dirs, files in os.walk(fam_dir):
        for f in files:
            if f == "conn.log":
                fp = os.path.join(root, f)
                df = load_conn_log(fp, family)
                if df is not None:
                    OUTPUT.append(df)

print("\n[+] Combining all logs...")

if len(OUTPUT) == 0:
    print("[!] ERROR: No valid logs found.")
else:
    final = pd.concat(OUTPUT, ignore_index=True)
    final.to_csv("ransomware_conn_dataset.csv", index=False)
    print("[+] Saved dataset as ransomware_conn_dataset.csv")
    print("[+] Rows:", len(final))
    print("[+] Done.")
