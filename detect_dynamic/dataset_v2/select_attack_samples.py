#!/usr/bin/env python3

import csv
import re
import subprocess
from pathlib import Path

SAMPLE_ROOT = Path.home() / "malware_samples"
OUTPUT = Path(__file__).resolve().parent / "attack_manifest_1st.csv"

MAX_PER_FAMILY = 2
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def is_x86_64(path: Path) -> bool:
    try:
        result = subprocess.run(
            ["file", "-b", str(path)],
            capture_output=True,
            text=True,
            check=False,
        )
        return "x86-64" in result.stdout
    except Exception:
        return False


def main():
    if not SAMPLE_ROOT.exists():
        raise SystemExit(f"[ERROR] sample directory not found: {SAMPLE_ROOT}")

    selected = []

    family_dirs = sorted(
        [p for p in SAMPLE_ROOT.iterdir() if p.is_dir()],
        key=lambda p: p.name.lower(),
    )

    for family_dir in family_dirs:
        family = family_dir.name
        candidates = []

        for path in sorted(family_dir.glob("*.elf")):
            sha256 = path.stem.lower()

            if not SHA256_RE.fullmatch(sha256):
                continue

            if not is_x86_64(path):
                continue

            candidates.append((sha256, path))

        for sha256, path in candidates[:MAX_PER_FAMILY]:
            sample_id = f"{family}_{sha256[:8]}_001"

            selected.append({
                "Sample_ID": sample_id,
                "Family": family,
                "SHA256": sha256,
                "Root_EXE": str(path.resolve()),
                "Raw_JSONL": f"/mnt/guardfs_logs/raw/attack/{sample_id}.jsonl",
                "Status": "PENDING",
                "Notes": "1st collection; x86-64; family-balanced selection",
            })

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "Sample_ID",
                "Family",
                "SHA256",
                "Root_EXE",
                "Raw_JSONL",
                "Status",
                "Notes",
            ],
        )
        writer.writeheader()
        writer.writerows(selected)

    print(f"[OK] manifest: {OUTPUT}")
    print(f"[OK] selected samples: {len(selected)}")

    counts = {}
    for row in selected:
        counts[row["Family"]] = counts.get(row["Family"], 0) + 1

    print(f"[OK] selected families: {len(counts)}")
    for family, count in sorted(counts.items(), key=lambda x: x[0].lower()):
        print(f"  {family}: {count}")


if __name__ == "__main__":
    main()
