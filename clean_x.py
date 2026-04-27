import pandas as pd

X = pd.read_csv("X.csv")

# Columns that should be numeric
num_cols = ["duration", "orig_bytes", "resp_bytes"]

for col in num_cols:
    X[col] = pd.to_numeric(X[col], errors="coerce")  # converts "-" to NaN, or anything weird to NaN
    X[col].fillna(0, inplace=True)                  # replace NaN with 0 (or any strategy you want)

X.to_csv("X_clean.csv", index=False)
print(X.dtypes)
