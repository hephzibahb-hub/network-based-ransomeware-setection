import pandas as pd

df = pd.read_csv("ransomware_conn_dataset.csv")

# y = label
y = df["family"]

# X = everything except label
X = df.drop(columns=["family"])

X.to_csv("X.csv", index=False)
y.to_csv("y.csv", index=False)

print("[+] Saved X.csv and y.csv")
print("Rows:", len(df))
print("Features:", X.shape[1])
