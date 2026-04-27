import pandas as pd

y = pd.read_csv("y.csv")

# Count family occurrences
counts = y["family"].value_counts()

# Threshold: merge families with less than 50 samples
THRESHOLD = 50
small_families = counts[counts < THRESHOLD].index.tolist()

print("[+] Families merged into OTHER:", small_families)

# Replace tiny families with "Other"
y["family"] = y["family"].apply(lambda x: x if x not in small_families else "Other")

# Save new y file
y.to_csv("y_merged.csv", index=False)

print("[+] Saved y_merged.csv")
print("New class distribution:")
print(y["family"].value_counts())
