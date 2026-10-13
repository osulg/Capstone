#!/usr/bin/env python3
"""
수집 로그 → 샘플 단위 피처 CSV (Task 5, 정상·악성 공용).

샘플 단위는 eBPF run 파일(<run_id>.ebpf.jsonl)이다. 한 파일 = 한 실행 = 한 행.
프로세스 트리를 eBPF가 확정하므로 라벨을 자동으로 붙일 수 있다(수동 PID 지정 금지).

엔트로피는 FUSE 수집 로그(*.fuse.jsonl)에서 같은 실행 구간·PID·경로로 매칭해 채운다.
FUSE 로그가 없으면 엔트로피 관련 피처는 0/비활성으로 남는다.

라벨: --labels CSV(run_id, label[, family/type ...])에서 가져온다. benign_runs.csv를
그대로 쓸 수 있다. 라벨을 못 찾은 run은 label=-1(unknown)로 남겨 감사에 활용한다.

사용:
  python3 logs_to_csv.py --collect-dir ~/guardfs_runtime/collect \
      --labels ~/guardfs_runtime/collect/benign_runs.csv \
      --out features.csv
"""

import argparse
import csv
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from features import FEATURE_ORDER, compute_features, merge_entropy  # noqa: E402

META_COLS = ["run_id", "label", "family", "source", "root_pid",
             "kernel_drops", "processing_errors", "n_records"]


def load_jsonl(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def load_labels(paths):
    """run_id -> {'label': int, 'family': str}"""
    labels = {}
    for path in paths:
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                rid = row.get("run_id")
                if not rid:
                    continue
                raw = (row.get("label") or "").strip().lower()
                label = {"benign": 0, "0": 0, "malicious": 1, "attack": 1, "1": 1}.get(raw, -1)
                labels[rid] = {
                    "label": label,
                    "family": row.get("family") or row.get("Type") or "",
                }
    return labels


def load_meta(path):
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            pass
    return {}


def index_fuse_by_run(collect_dir):
    """run_id -> FUSE 레코드 목록. 파일명이 <run_id>.fuse.jsonl이면 직접 매칭."""
    per_run = {}
    session = []
    for path in glob.glob(os.path.join(collect_dir, "*.fuse.jsonl")):
        run_id = os.path.basename(path)[: -len(".fuse.jsonl")]
        recs = load_jsonl(path)
        per_run[run_id] = recs
        session.extend(recs)
    return per_run, session


def fuse_for_run(run_id, meta, per_run, session):
    """이 run에 해당하는 FUSE 레코드. 전용 파일이 있으면 그걸, 아니면 세션에서 구간·트리로 거른다."""
    if run_id in per_run:
        return per_run[run_id]
    if not session:
        return []

    start = meta.get("start_monotonic_ns")
    end = meta.get("end_monotonic_ns")
    if start is None or end is None:
        return []

    # FUSE와 eBPF는 같은 CLOCK_MONOTONIC을 쓰므로 구간 비교가 가능하다.
    return [r for r in session if start <= r.get("ts_ns", -1) <= end]


def main():
    p = argparse.ArgumentParser(description="수집 로그 → 피처 CSV")
    p.add_argument("--collect-dir", required=True)
    p.add_argument("--labels", action="append", default=[],
                   help="run_id→label CSV (여러 번 지정 가능)")
    p.add_argument("--out", required=True)
    p.add_argument("--min-events", type=int, default=1,
                   help="이벤트가 이보다 적은 run은 제외")
    args = p.parse_args()

    labels = load_labels(args.labels)
    per_run_fuse, session_fuse = index_fuse_by_run(args.collect_dir)

    ebpf_files = sorted(glob.glob(os.path.join(args.collect_dir, "*.ebpf.jsonl")))
    if not ebpf_files:
        print(f"[logs_to_csv] eBPF 로그가 없습니다: {args.collect_dir}", file=sys.stderr)
        return 1

    rows = []
    unknown = 0
    for path in ebpf_files:
        run_id = os.path.basename(path)[: -len(".ebpf.jsonl")]
        ebpf = load_jsonl(path)
        if len(ebpf) < args.min_events:
            continue

        meta = load_meta(os.path.join(args.collect_dir, f"{run_id}.ebpf.meta.json"))
        fuse = fuse_for_run(run_id, meta, per_run_fuse, session_fuse)
        merged = merge_entropy(ebpf, fuse)

        feats = compute_features(merged)
        lab = labels.get(run_id, {"label": -1, "family": ""})
        if lab["label"] == -1:
            unknown += 1

        row = {
            "run_id": run_id,
            "label": lab["label"],
            "family": lab["family"],
            "source": "ebpf+fuse" if fuse else "ebpf",
            "root_pid": meta.get("root_pid"),
            "kernel_drops": meta.get("kernel_drops"),
            "processing_errors": meta.get("processing_errors"),
            "n_records": len(ebpf),
        }
        row.update(feats)
        rows.append(row)

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=META_COLS + FEATURE_ORDER)
        writer.writeheader()
        writer.writerows(rows)

    n_labeled = sum(1 for r in rows if r["label"] != -1)
    print(f"[logs_to_csv] {len(rows)}개 샘플 → {args.out} "
          f"(라벨 있음 {n_labeled}, unknown {unknown})")
    if rows:
        dist = {}
        for r in rows:
            dist[r["label"]] = dist.get(r["label"], 0) + 1
        print(f"[logs_to_csv] 라벨 분포: {dist}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
