import os

ROOT = "malicious"

def validate_conn_log(filepath):
    try:
        with open(filepath, "r", errors="ignore") as f:
            lines = f.readlines()

        separator = "\t"
        fields = None

        # Detect #separator and #fields dynamically
        for line in lines:
            if line.startswith("#separator"):
                raw = line.split()[-1]
                separator = raw.encode().decode("unicode_escape")

            elif line.startswith("#fields"):
                # FIX: skip only '#fields', NOT the next token
                parts = line.strip().split()
                fields = parts[1:]  # <-- CORRECT FIX
                break

        if fields is None:
            return False, "Missing #fields header"

        expected = len(fields)

        # Validate every data row
        for line in lines:
            if line.startswith("#"):
                continue

            cols = line.rstrip("\n").split(separator)

            if len(cols) != expected:
                return False, f"Bad column count ({len(cols)} != {expected})"

        return True, "OK"

    except Exception as e:
        return False, f"Error: {e}"


# Walk through families
for family in sorted(os.listdir(ROOT)):
    family_dir = os.path.join(ROOT, family)

    if not os.path.isdir(family_dir):
        continue

    print(f"\n=== Checking {family} ===")

    for root, dirs, files in os.walk(family_dir):
        for f in files:
            if f == "conn.log":
                path = os.path.join(root, f)
                valid, msg = validate_conn_log(path)
                mark = "✔" if valid else "X"
                print(f" {mark} {path}: {msg}")
