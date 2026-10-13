#!/usr/bin/env python3
"""
정적(byte 3-gram) + 동적(행동 RF) fusion 평가.

- 정적 점수: 각 run의 실행 바이너리를 StaticAnalyzer로 → P(악성)
    · 악성 run: meta의 command[0](악성 ELF). 없으면 --malware-base에서 sha로 검색
    · 정상 run: meta의 command[0](sh/도구) 바이너리
- 동적 점수: features.csv를 RandomForest 5-fold CV proba
- fusion: 평균 / OR(최댓값)

⚠️ 정적 모델(static_rf_n3_k1000.pkl)은 sklearn 1.3.2로 학습됨.
   다른 버전이면 결과가 깨진다(스크립트가 /bin/ls 점수로 자가진단).
   권장: python3 -m venv venv_static && pip install scikit-learn==1.3.2 joblib numpy pandas

사용:
  python3 models/dynamic/collect/eval_fusion.py \
      --features models/dynamic/dataset_v4/features.csv \
      --collect-dir <ebpf.meta.json 들이 있는 폴더> \
      --malware-base ~/malware
"""
import argparse
import glob
import json
import os
import shutil
import sys

import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.realpath(os.path.join(HERE, "..", "..", ".."))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", required=True)
    ap.add_argument("--collect-dir", required=True,
                    help="<run_id>.ebpf.meta.json 들이 있는 폴더")
    ap.add_argument("--malware-base", default=os.path.expanduser("~/malware"))
    ap.add_argument("--vocab", default=os.path.join(REPO, "models/static/byte_ngram_vocab_n3_k1000.json"))
    ap.add_argument("--model", default=os.path.join(REPO, "models/static/static_rf_n3_k1000.pkl"))
    ap.add_argument("--thr", type=float, default=0.5)
    ap.add_argument("--out", default="fusion_scores.csv")
    args = ap.parse_args()

    sys.path.insert(0, os.path.join(REPO, "guardfs/stage2"))
    sys.path.insert(0, os.path.join(REPO, "models/dynamic/collect"))
    from static_analyzer import StaticAnalyzer
    from features import FEATURE_ORDER
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import StratifiedKFold, cross_val_predict

    sa = StaticAnalyzer(args.vocab, args.model)

    # --- 자가진단: 정적 모델이 올바른 sklearn 버전에서 도는지 ---
    ls = shutil.which("ls")
    ls_score = sa._predict(sa._extract_path(ls)) if ls else None
    print(f"[진단] /bin/ls 정적점수 = {ls_score} (정상이면 ~0.005; 1 넘거나 높으면 sklearn 버전 불일치)")
    if ls_score is None or ls_score > 0.3:
        print("[경고] 정적 모델 출력이 비정상입니다. sklearn==1.3.2 환경에서 실행하세요.", file=sys.stderr)

    df = pd.read_csv(args.features)

    def bin_path(rid, label):
        meta = os.path.join(args.collect_dir, f"{rid}.ebpf.meta.json")
        cmd = None
        if os.path.exists(meta):
            try:
                cmd = json.load(open(meta, encoding="utf-8")).get("command")
            except Exception:
                cmd = None
        if label == 1:
            if cmd and os.path.exists(cmd[0]):
                return cmd[0]
            parts = rid.split("_")
            sha = parts[-2] if len(parts) >= 2 else ""
            hits = glob.glob(os.path.join(args.malware_base, "*", sha + "*"))
            return hits[0] if hits else None
        else:
            if cmd:
                exe = cmd[0]
                return exe if os.path.exists(exe) else shutil.which(exe)
            return None

    static_probs, missing = [], 0
    for _, r in df.iterrows():
        p = bin_path(r.run_id, int(r.label))
        v = sa._predict(sa._extract_path(p)) if p else None
        if v is None:
            missing += 1
            v = 0.0
        static_probs.append(float(np.clip(v, 0, 1)))
    df["static_prob"] = static_probs
    if missing:
        print(f"[주의] 바이너리를 못 찾아 정적점수 0 처리한 run: {missing}개")

    # --- 동적 점수 (RF 5-fold CV) ---
    X = df[FEATURE_ORDER].to_numpy(float)
    y = df.label.to_numpy(int)
    rf = RandomForestClassifier(n_estimators=400, random_state=42, class_weight="balanced")
    df["dyn_prob"] = cross_val_predict(
        rf, X, y, cv=StratifiedKFold(5, shuffle=True, random_state=42),
        method="predict_proba")[:, 1]

    nb, nm = int((y == 0).sum()), int((y == 1).sum())
    print(f"\n샘플: 정상 {nb} + 악성 {nm}")
    print(f"정적점수 평균 — 악성 {df[df.label==1].static_prob.mean():.3f} / 정상 {df[df.label==0].static_prob.mean():.3f}\n")

    def report(name, score):
        pred = (np.asarray(score) >= args.thr).astype(int)
        tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
        fn = int(((pred == 0) & (y == 1)).sum()); tn = int(((pred == 0) & (y == 0)).sum())
        rec = tp / (tp + fn) if tp + fn else 0
        fpr = fp / (fp + tn) if fp + tn else 0
        prec = tp / (tp + fp) if tp + fp else 0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
        print(f"  {name:14} 탐지율 {rec:5.1%}  오탐률 {fpr:5.1%}  정밀도 {prec:5.1%}  F1 {f1:.2f}  (오탐 {fp}, 미탐 {fn})")

    print(f"=== 성능 (임계값 {args.thr}) ===")
    report("정적만", df.static_prob)
    report("동적만", df.dyn_prob)
    report("fusion-평균", (df.static_prob + df.dyn_prob) / 2)
    report("fusion-OR", np.maximum(df.static_prob, df.dyn_prob))

    df.to_csv(args.out, index=False)
    print(f"\n저장: {args.out} (run_id별 static_prob/dyn_prob 포함)")


if __name__ == "__main__":
    sys.exit(main())
