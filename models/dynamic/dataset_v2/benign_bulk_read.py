from pathlib import Path

target = Path.home() / "holdfs_benign_read"

for path in sorted(target.glob("*.txt")):
    with open(path, "r", encoding="utf-8") as f:
        _ = f.read()

print("benign bulk read complete")
