#!/usr/bin/env python3
"""
FUSE-only · PID 단위 피처 추출 (동적 모델 v5용).

왜 v5인가:
  런타임(detection)은 FUSE 이벤트만 보고, PID 단위로 Stage2에 점수를 매긴다.
  기존 v4(features.csv)는 eBPF+FUSE 합본을 run 단위로 집계해서 런타임과 입력이
  어긋났다(proc_count·crypto·EXEC/EXIT 등). v5는 런타임이 실제로 보는 신호에
  맞춘다: *.fuse.jsonl 만 사용하고, PID 단위로 집계한다.

재수집 안 함: 이미 모은 *.fuse.jsonl 로그를 다시 "계산"만 한다.

라벨링(중요):
  - 정상 run: 모든 PID label=0
  - 악성 run: 악성 프로세스 서브트리의 PID만 label=1, 그 외(prep/수집 하네스)는
    label=0. 서브트리는 <run_id>.ebpf.meta.json 의 root_pid 와
    <run_id>.ebpf.jsonl 의 (pid,ppid) lineage 로 계산한다. (eBPF 로그는 라벨링
    '빌드 타임'에만 쓰인다 — 런타임 탐지기는 여전히 FUSE-only다.)

제외 피처: proc_count(PID 단위면 항상 1), crypto_calls(FUSE엔 CRYPTO op 없음).
  → features.py의 24피처 중 이 둘을 뺀 22피처가 v5 스키마다.

사용:
  python3 models/dynamic/collect/extract_perpid_fuse.py \
      --collect-dir ~/guardfs_runtime/collect \
      --labels ~/guardfs_runtime/collect/benign_runs.csv \
      --labels ~/malware_runs.csv \
      --ebpf-dir /var/log/guardfs \
      --out models/dynamic/dataset_v5/features_perpid.csv
"""
import argparse
import csv
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from features import FEATURE_ORDER, compute_features  # noqa: E402

# PID 단위 FUSE-only에서 의미 없는/만들 수 없는 피처 제외
DROP = {"proc_count", "crypto_calls"}
FEATURE_ORDER_V5 = [c for c in FEATURE_ORDER if c not in DROP]

META_COLS = ["run_id", "pid", "label", "family", "workload", "n_events"]


def load_jsonl(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return out


def load_labels(paths):
    """run_id -> {'label': int(0/1/-1), 'family': str}"""
    labels = {}
    for path in paths:
        if not os.path.exists(path):
            print(f"[extract] 경고: 라벨 파일 없음 {path}", file=sys.stderr)
            continue
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                rid = row.get("run_id")
                if not rid:
                    continue
                raw = (row.get("label") or "").strip().lower()
                label = {"benign": 0, "0": 0,
                         "malicious": 1, "attack": 1, "1": 1}.get(raw, -1)
                labels[rid] = {
                    "label": label,
                    "family": row.get("family") or row.get("Type") or "",
                }
    return labels


def workload_of(run_id):
    """benign_bulk_copy_10x4k_1 -> bulk_copy / lockbit_4dc06_001 -> lockbit"""
    s = run_id
    for p in ("benign_", "malware_"):
        if s.startswith(p):
            s = s[len(p):]
            break
    parts = s.split("_")
    while parts and (parts[-1].isdigit()
                     or parts[-1].replace("k", "").replace("x", "").isdigit()
                     or (len(parts[-1]) in (6, 7, 8)
                         and all(c in "0123456789abcdef" for c in parts[-1]))):
        parts.pop()
    return "_".join(parts) or s


def malicious_subtree(run_id, ebpf_dirs):
    """악성 서브트리 PID 집합. (root_pid + ebpf lineage). 없으면 None(→폴백)."""
    meta = None
    ebpf = None
    for d in ebpf_dirs:
        mp = os.path.join(d, f"{run_id}.ebpf.meta.json")
        ep = os.path.join(d, f"{run_id}.ebpf.jsonl")
        if meta is None and os.path.exists(mp):
            try:
                meta = json.load(open(mp, encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pass
        if ebpf is None and os.path.exists(ep):
            ebpf = load_jsonl(ep)
    if not meta or meta.get("root_pid") is None:
        return None
    root = int(meta["root_pid"])

    # pid -> ppid (eBPF가 있으면 전체 lineage, 없으면 FUSE에서 뒤에 채움)
    parent = {}
    if ebpf:
        for r in ebpf:
            pid, ppid = r.get("pid"), r.get("ppid")
            if pid is not None and ppid is not None and pid not in parent:
                parent[pid] = ppid

    # root 자손 판정: ppid 체인을 타고 올라가 root를 만나면 악성
    def in_subtree(pid):
        seen = set()
        cur = pid
        while cur is not None and cur not in seen:
            if cur == root:
                return True
            seen.add(cur)
            cur = parent.get(cur)
        return False

    return {root, *(p for p in parent if in_subtree(p))}, parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--collect-dir", required=True,
                    help="*.fuse.jsonl 들이 있는 폴더")
    ap.add_argument("--labels", action="append", default=[],
                    help="run_id→label CSV (여러 번 지정 가능)")
    ap.add_argument("--ebpf-dir", action="append", default=[],
                    help="<run_id>.ebpf.* 위치(라벨링용). 기본: collect-dir")
    ap.add_argument("--out", required=True)
    ap.add_argument("--min-events", type=int, default=3,
                    help="이벤트가 이보다 적은 PID는 제외 (잡음 제거)")
    args = ap.parse_args()

    labels = load_labels(args.labels)
    ebpf_dirs = args.ebpf_dir or [args.collect_dir]
    if args.collect_dir not in ebpf_dirs:
        ebpf_dirs = ebpf_dirs + [args.collect_dir]

    fuse_files = sorted(glob.glob(os.path.join(args.collect_dir, "*.fuse.jsonl")))
    if not fuse_files:
        print(f"[extract] FUSE 로그 없음: {args.collect_dir}", file=sys.stderr)
        return 1

    rows = []
    n_mal_runs = n_coarse = 0
    for path in fuse_files:
        run_id = os.path.basename(path)[: -len(".fuse.jsonl")]
        recs = load_jsonl(path)
        if not recs:
            continue

        lab = labels.get(run_id, {"label": -1, "family": ""})
        run_label = lab["label"]
        family = lab["family"]
        workload = workload_of(run_id)

        mal_pids = None
        if run_label == 1:
            n_mal_runs += 1
            sub = malicious_subtree(run_id, ebpf_dirs)
            if sub is None:
                # 폴백: lineage 정보가 없으면 run 전체를 악성으로(거칠게) 본다.
                n_coarse += 1
                mal_pids = "ALL"
            else:
                mal_pids = sub[0]

        # PID 단위로 묶기
        by_pid = {}
        for r in recs:
            pid = r.get("pid")
            if pid is None:
                continue
            by_pid.setdefault(pid, []).append(r)

        for pid, precs in by_pid.items():
            if len(precs) < args.min_events:
                continue
            feats = compute_features(precs)
            if run_label == 0:
                plabel = 0
            elif run_label == 1:
                plabel = 1 if (mal_pids == "ALL" or pid in mal_pids) else 0
            else:
                plabel = -1
            row = {
                "run_id": run_id, "pid": pid, "label": plabel,
                "family": family if plabel == 1 else "",
                "workload": workload, "n_events": len(precs),
            }
            row.update({c: feats[c] for c in FEATURE_ORDER_V5})
            rows.append(row)

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=META_COLS + FEATURE_ORDER_V5)
        w.writeheader()
        w.writerows(rows)

    nb = sum(1 for r in rows if r["label"] == 0)
    nm = sum(1 for r in rows if r["label"] == 1)
    nu = sum(1 for r in rows if r["label"] == -1)
    print(f"[extract] {len(rows)} PID-샘플 → {args.out}")
    print(f"[extract]   정상 {nb} / 악성 {nm} / unknown {nu}")
    print(f"[extract]   악성 run {n_mal_runs}개 중 lineage 없어 거칠게 라벨한 run: {n_coarse}")
    if nm:
        fams = {}
        for r in rows:
            if r["label"] == 1:
                fams[r["family"]] = fams.get(r["family"], 0) + 1
        print(f"[extract]   악성 패밀리별 PID 수: {dict(sorted(fams.items()))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
