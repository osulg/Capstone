#!/usr/bin/env python3

import csv
import hashlib
import json
import shutil
import subprocess
from collections import Counter
from pathlib import Path

BASE = Path("/mnt/guardfs_logs")
MANIFEST = BASE / "attack_manifest_1st.csv"
STATE = BASE / "collection_state.csv"
CURRENT = BASE / "tools" / "current_sample.json"

REPO = Path.home() / "Capstone_dynamic_ml"
BPF = REPO / "detect_dynamic" / "bpf.py"

TARGET = Path.home() / "attack_target"
DOCS = TARGET / "docs"

PROFILES = {
    "Babuk": {
        "verified": True,
        "format": "<ELF> <TARGET_PATH>",
        "note": "기존 runner에서 대상 경로 인자 사용 확인",
    },
    "IceFire": {
        "verified": True,
        "format": "<ELF> <TARGET_PATH>",
        "note": "기존 runner에서 대상 경로 인자 사용 확인",
    },
    "lockbit": {
        "verified": True,
        "format": "<ELF> <TARGET_PATH>",
        "note": "기존 runner에서 대상 경로 인자 사용 확인",
    },
    "AvosLocker": {
        "verified": True,
        "format": "<ELF> <THREAD_COUNT> <TARGET_PATH>",
        "note": "기존 runner에서 thread count + 대상 경로 사용 확인",
    },
    "HelloKitty": {
        "verified": True,
        "format": "<ELF> -m <THREAD_COUNT> <TARGET_PATH>",
        "note": "기존 runner에서 -m 옵션 + 대상 경로 사용 확인",
    },
    "MONTI": {
        "verified": True,
        "format": "<ELF> --path <TARGET_PATH>",
        "note": "기존 runner에서 --path 사용 확인",
    },
    "REvil": {
        "verified": True,
        "format": "<ELF> --path <TARGET_PATH>",
        "note": "기존 runner에서 --path 사용 확인",
    },
    "BlackCat": {
        "verified": True,
        "format": "<ELF> [TOKEN OPTION] -p <TARGET_PATH> --verbose",
        "note": "기존 runner에서 대상 경로 옵션 사용 확인",
    },
    "blackcat": {
        "verified": True,
        "format": "<ELF> [TOKEN OPTION] -p <TARGET_PATH> --verbose",
        "note": "기존 runner에서 대상 경로 옵션 사용 확인",
    },
}


def load_manifest():
    with MANIFEST.open(encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_state():
    if not STATE.exists():
        return {}

    result = {}

    with STATE.open(encoding="utf-8") as f:
        for row in csv.DictReader(f):
            result[row["Sample_ID"]] = row["Status"]

    return result


def save_state(state):
    with STATE.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["Sample_ID", "Status"]
        )
        writer.writeheader()

        for sample_id, status in state.items():
            writer.writerow({
                "Sample_ID": sample_id,
                "Status": status
            })


def get_status(row, state):
    return state.get(row["Sample_ID"], row["Status"])


def pending_rows(family=None):
    rows = load_manifest()
    state = load_state()

    result = []

    for row in rows:
        if get_status(row, state) != "PENDING":
            continue

        if family is not None and row["Family"] != family:
            continue

        result.append(row)

    return result


def next_pending():
    rows = pending_rows()

    if not rows:
        return None

    return rows[0]


def choose_family():
    rows = pending_rows()

    if not rows:
        print("[DONE] PENDING 샘플이 없음")
        return None

    counts = Counter(row["Family"] for row in rows)
    families = sorted(counts)

    print()
    print("=== PENDING FAMILY ===")

    for i, family in enumerate(families, 1):
        print(f"{i:2}. {family} ({counts[family]})")

    print(" 0. 취소")

    try:
        choice = int(input("> ").strip())
    except ValueError:
        print("[FAIL] 숫자를 입력하세요.")
        return None

    if choice == 0:
        return None

    if choice < 1 or choice > len(families):
        print("[FAIL] 잘못된 번호")
        return None

    family = families[choice - 1]
    candidates = pending_rows(family)

    print()
    print(f"[SELECT] {family}")
    print(f"[SELECT] PENDING {len(candidates)}개 중 첫 번째 샘플 선택")

    return candidates[0]


def load_current():
    if not CURRENT.exists():
        return None

    with CURRENT.open(encoding="utf-8") as f:
        return json.load(f)


def save_current(row):
    CURRENT.parent.mkdir(parents=True, exist_ok=True)

    with CURRENT.open("w", encoding="utf-8") as f:
        json.dump(row, f, indent=2)


def sha256(path):
    h = hashlib.sha256()

    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)

            if not chunk:
                break

            h.update(chunk)

    return h.hexdigest()


def verify(row):
    sample = Path(row["Root_EXE"])

    print()
    print("=== SAMPLE VERIFY ===")
    print("Sample_ID :", row["Sample_ID"])
    print("Family    :", row["Family"])
    print("SHA256    :", row["SHA256"])
    print("Root_EXE  :", sample)
    print("JSONL     :", row["Raw_JSONL"])

    if not sample.exists():
        print("[FAIL] ELF 파일 없음")
        return False

    actual = sha256(sample)

    if actual != row["SHA256"]:
        print("[FAIL] SHA256 불일치")
        print("Actual:", actual)
        return False

    result = subprocess.run(
        ["file", "-b", str(sample)],
        capture_output=True,
        text=True
    )

    print("File      :", result.stdout.strip())

    if "x86-64" not in result.stdout:
        print("[FAIL] x86-64가 아님")
        return False

    print("[OK] SHA256 / x86-64 검증 완료")
    return True

def show_profile(row):
    family = row["Family"]
    profile = PROFILES.get(family)

    print()
    print("=== EXECUTION PROFILE ===")
    print("Family :", family)

    if profile is None:
        print("실행 형식 확인됨 : NO")
        print("상태             : UNSUPPORTED / 별도 확인 필요")
        return False

    print("실행 형식 확인됨 : YES")
    print("기존 형식        :", profile["format"])
    print("설명             :", profile["note"])
    print("권한             : 일반 사용자 권한만 사용")
    return True

def prepare_row(row):
    if row is None:
        print("[DONE] 준비할 PENDING 샘플이 없음")
        return

    if not verify(row):
        return

    show_profile(row)

    if TARGET.is_symlink():
        print("[FAIL] attack_target이 symlink임. 중단.")
        return

    if TARGET.exists():
        shutil.rmtree(TARGET)

    DOCS.mkdir(parents=True)

    test_exts = [
        "txt", "doc", "docx", "pdf",
        "xls", "xlsx", "ppt", "pptx",
        "html", "ps", "jpg", "png",
        "csv", "json", "xml", "log",
        "bak", "db", "sql", "unk",
    ]

    for i, ext in enumerate(test_exts, 1):
        p = DOCS / f"file_{i:02d}.{ext}"
        p.write_bytes(
            (
                f"GuardFS benign test file\n"
                f"index={i}\n"
                f"extension={ext}\n"
                f"sample={row['Sample_ID']}\n"
            ).encode("utf-8")
        )

    hash_dir = BASE / "hashes"
    hash_dir.mkdir(parents=True, exist_ok=True)

    before_hash = hash_dir / f"{row['Sample_ID']}_before.sha256"

    with before_hash.open("w", encoding="utf-8") as f:
        for p in sorted(DOCS.iterdir()):
            if not p.is_file():
                continue

            digest = sha256(p)
            f.write(f"{digest}  {p.name}\n")
    save_current(row)

    print()
    print("=== READY ===")
    print("Sample_ID   :", row["Sample_ID"])
    print("Family      :", row["Family"])
    print("테스트 파일 : 20개")
    print("Before hash :", before_hash)
    print()
    print("Collector를 시작하려면 메뉴 3번")


def prepare_next():
    prepare_row(next_pending())


def prepare_family():
    prepare_row(choose_family())

def sudo_exists(path):
    result = subprocess.run(
        ["sudo", "test", "-e", str(path)],
        check=False
    )
    return result.returncode == 0

def start_collector():
    row = load_current()

    if row is None:
        print("[FAIL] 먼저 샘플을 준비하세요.")
        return

    if not verify(row):
        return

    log_path = Path(row["Raw_JSONL"])

    if sudo_exists(log_path):
        print("[STOP] 이미 JSONL이 존재함:")
        print(log_path)
        print("기존 데이터 혼합 방지를 위해 시작하지 않음.")
        return

    print()
    print("=== COLLECTOR START ===")
    print("Sample :", row["Sample_ID"])
    print("Family :", row["Family"])
    print("Root   :", row["Root_EXE"])
    print("Log    :", row["Raw_JSONL"])
    print()
    print("90초 동안 collector 실행")
    print("이 helper는 악성 샘플을 자동 실행하지 않음.")
    print()

    cmd = [
        "sudo",
        "env",
        f"GUARDFS_TARGET_DIR={TARGET}/",
        f"GUARDFS_ROOT_EXE={row['Root_EXE']}",
        f"GUARDFS_LOG_FILE={row['Raw_JSONL']}",
        "timeout",
        "90s",
        "/usr/bin/python3",
        str(BPF),
    ]

    subprocess.run(cmd)


def summarize():
    row = load_current()

    if row is None:
        print("[FAIL] 현재 선택된 샘플 없음")
        return

    log_path = Path(row["Raw_JSONL"])

    print()
    print("=== COLLECTION SUMMARY ===")
    print("Sample_ID :", row["Sample_ID"])

    # -------------------------
    # 1. JSONL 요약
    # -------------------------
    if sudo_exists(log_path):
        result = subprocess.run(
            ["sudo", "cat", str(log_path)],
            capture_output=True,
            text=True
        )

        total = 0
        labels = {}
        actions = {}
        relations = {}

        if result.returncode == 0:
            for line in result.stdout.splitlines():
                try:
                    obj = json.loads(line)
                except Exception:
                    continue

                total += 1

                label = str(obj.get("label", "?"))
                labels[label] = labels.get(label, 0) + 1

                action = str(obj.get("type", obj.get("action", "?")))
                actions[action] = actions.get(action, 0) + 1

                relation = str(obj.get("relation", "?"))
                relations[relation] = relations.get(relation, 0) + 1

        print("Events    :", total)
        print("Labels    :", labels)
        print("Actions   :", actions)
        print("Relations :", relations)

    else:
        print("JSONL     : 없음")

    # -------------------------
    # 2. 실행 전/후 파일 비교
    # -------------------------
    hash_dir = BASE / "hashes"

    before_path = hash_dir / f"{row['Sample_ID']}_before.sha256"
    after_path = hash_dir / f"{row['Sample_ID']}_after.sha256"

    if not before_path.exists():
        print("[FAIL] Before hash 없음:", before_path)
        return

    before = {}

    with before_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")

            if "  " not in line:
                continue

            digest, name = line.split("  ", 1)
            before[name] = digest

    after = {}

    if DOCS.exists():
        for p in sorted(DOCS.iterdir()):
            if not p.is_file():
                continue

            after[p.name] = sha256(p)

    with after_path.open("w", encoding="utf-8") as f:
        for name in sorted(after):
            f.write(f"{after[name]}  {name}\n")

    unchanged = []
    modified = []
    deleted = []
    created = []

    for name, old_hash in before.items():
        if name not in after:
            deleted.append(name)
        elif after[name] == old_hash:
            unchanged.append(name)
        else:
            modified.append(name)

    for name in after:
        if name not in before:
            created.append(name)

    print()
    print("=== FILE CHANGE SUMMARY ===")
    print("Unchanged :", len(unchanged))
    print("Modified  :", len(modified))
    print("Deleted   :", len(deleted))
    print("Created   :", len(created))
    print("After hash:", after_path)

    if modified:
        print("Modified files:", ", ".join(modified))

    if deleted:
        print("Deleted files :", ", ".join(deleted))

    if created:
        print("Created files :", ", ".join(created))

def mark(status):
    row = load_current()

    if row is None:
        print("[FAIL] 현재 선택된 샘플 없음")
        return

    state = load_state()
    state[row["Sample_ID"]] = status
    save_state(state)

    print(f"[OK] {row['Sample_ID']} -> {status}")

    if CURRENT.exists():
        CURRENT.unlink()


def show_current():
    row = load_current()

    if row is None:
        print("[INFO] 현재 선택된 샘플 없음")
        return

    print()
    print("=== CURRENT SAMPLE ===")
    print("Sample_ID :", row["Sample_ID"])
    print("Family    :", row["Family"])
    print("SHA256    :", row["SHA256"])
    print("Root_EXE  :", row["Root_EXE"])
    print("JSONL     :", row["Raw_JSONL"])


def show_progress():
    rows = load_manifest()
    state = load_state()

    counts = Counter()

    for row in rows:
        counts[get_status(row, state)] += 1

    print()
    print("=== PROGRESS ===")
    print("전체:", len(rows))

    for status in ["PENDING", "DONE", "SKIP", "FAILED"]:
        print(f"{status}: {counts.get(status, 0)}")


def main():
    while True:
        print()
        print("================================")
        print(" GuardFS v2 Attack Collector")
        print("================================")
        print("1. 다음 PENDING 샘플 준비")
        print("2. Family 선택해서 샘플 준비")
        print("3. Collector 시작 (90초)")
        print("4. 현재 JSONL 결과 요약")
        print("5. 현재 샘플 DONE 처리")
        print("6. 현재 샘플 SKIP 처리")
        print("7. 현재 샘플 FAILED 처리")
        print("8. 현재 샘플 확인")
        print("9. 진행 현황")
        print("0. 종료")

        choice = input("> ").strip()

        if choice == "1":
            prepare_next()
        elif choice == "2":
            prepare_family()
        elif choice == "3":
            start_collector()
        elif choice == "4":
            summarize()
        elif choice == "5":
            mark("DONE")
        elif choice == "6":
            mark("SKIP")
        elif choice == "7":
            mark("FAILED")
        elif choice == "8":
            show_current()
        elif choice == "9":
            show_progress()
        elif choice == "0":
            break
        else:
            print("[FAIL] 잘못된 입력")


if __name__ == "__main__":
    main()
