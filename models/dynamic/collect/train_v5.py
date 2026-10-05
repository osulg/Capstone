#!/usr/bin/env python3
"""
동적 모델 v5 학습 (FUSE-only · PID 단위).

입력 : extract_perpid_fuse.py 가 만든 features_perpid.csv (22피처 + 메타)
출력 : rf_model_v5.pkl, feature_cols_v5.json, train_v5_report.json

평가(정직하게):
  1) StratifiedKFold OOF — dyn-only HIGH 임계값 스윕(FPR 0% 되는 최저값)
  2) 워크로드 그룹(GroupKFold) — 같은 워크로드가 train/val에 안 섞이게 한
     현실적 오탐률/탐지율
  3) Leave-One-Family-Out — 처음 보는 악성 패밀리 일반화

중요: 반드시 GuardFS venv(배포 때와 같은 sklearn)에서 실행해 pkl을 저장할 것.
      다른 버전에서 저장하면 런타임 로드시 predict_proba가 깨진다.

사용:
  python3 models/dynamic/collect/train_v5.py \
      --features models/dynamic/dataset_v5/features_perpid.csv \
      --out-model models/dynamic/rf_model_v5.pkl \
      --out-cols  models/dynamic/feature_cols_v5.json
"""
import argparse
import json
import os
import sys
import warnings

warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from extract_perpid_fuse import FEATURE_ORDER_V5  # noqa: E402


def rf():
    from sklearn.ensemble import RandomForestClassifier
    return RandomForestClassifier(
        n_estimators=400, random_state=42, class_weight="balanced")


def sweep(y, oof, nb, nm):
    print("\n=== dyn-only 임계값 스윕 (StratifiedKFold OOF) ===")
    print("  thr     FPR(정상)           탐지율(악성)")
    best = None
    table = []
    for thr in [round(t, 2) for t in np.arange(0.30, 0.96, 0.05)]:
        fp = int((oof[y == 0] >= thr).sum())
        tp = int((oof[y == 1] >= thr).sum())
        table.append({"thr": thr, "fpr": fp / nb, "recall": tp / nm,
                      "fp": fp, "tp": tp})
        mark = ""
        if fp == 0 and best is None:
            best = thr
            mark = "  <- FPR 0% 최저"
        print(f"  {thr:.2f}   {fp/nb:6.1%} ({fp:3d}/{nb})     "
              f"{tp/nm:6.1%} ({tp:2d}/{nm}){mark}")
    return best, table


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", required=True)
    ap.add_argument("--out-model", default=os.path.join(
        HERE, "..", "rf_model_v5.pkl"))
    ap.add_argument("--out-cols", default=os.path.join(
        HERE, "..", "feature_cols_v5.json"))
    ap.add_argument("--report", default=os.path.join(
        HERE, "..", "dataset_v5", "train_v5_report.json"))
    args = ap.parse_args()

    import joblib
    from sklearn.model_selection import (
        StratifiedKFold, GroupKFold, cross_val_predict)

    df = pd.read_csv(args.features)
    df = df[df.label.isin([0, 1])].reset_index(drop=True)
    X = df[FEATURE_ORDER_V5].to_numpy(float)
    y = df.label.to_numpy(int)
    nb, nm = int((y == 0).sum()), int((y == 1).sum())
    print(f"샘플(PID 단위): 정상 {nb} / 악성 {nm}  (피처 {len(FEATURE_ORDER_V5)}개)")
    if nm < 2 or nb < 2:
        print("[train] 경고: 한쪽 클래스가 너무 적어 CV가 무의미합니다.", file=sys.stderr)

    # 1) StratifiedKFold OOF → 임계값
    k = min(5, nb, nm)
    oof = cross_val_predict(
        rf(), X, y, cv=StratifiedKFold(k, shuffle=True, random_state=42),
        method="predict_proba")[:, 1]
    print(f"\n정상 OOF: 평균 {oof[y==0].mean():.3f} 최대 {oof[y==0].max():.3f}")
    print(f"악성 OOF: 평균 {oof[y==1].mean():.3f} 최소 {oof[y==1].min():.3f}")
    best, table = sweep(y, oof, nb, nm)
    margin = round(min(0.9, best + 0.05), 2) if best is not None else None
    if best is not None:
        rec = int((oof[y == 1] >= best).sum())
        print(f"\n→ FPR 0% 최저 임계값 ≈ {best} (탐지율 {rec}/{nm}={rec/nm:.1%})")
        print(f"→ 여유 둔 권장 STAGE2_DYN_ONLY_HIGH_THRESHOLD = {margin}")
    else:
        print("\n→ 0.95 이하 FPR 0% 임계값 없음 (정상에 고점수 PID 존재)")

    # 2) 워크로드 그룹 CV (현실적 FPR/탐지율)
    report = {"n_benign": nb, "n_malware": nm,
              "features": FEATURE_ORDER_V5, "threshold_sweep": table,
              "dyn_only_fpr0_threshold": best,
              "recommended_threshold": margin}
    if "workload" in df.columns and df["workload"].nunique() >= 3:
        groups = df["workload"].to_numpy()
        gk = min(5, df["workload"].nunique())
        goof = cross_val_predict(
            rf(), X, y, cv=GroupKFold(gk), groups=groups,
            method="predict_proba")[:, 1]
        thr = best if best is not None else 0.5
        gp = (goof >= thr).astype(int)
        tp = int(((gp == 1) & (y == 1)).sum()); fp = int(((gp == 1) & (y == 0)).sum())
        fn = int(((gp == 0) & (y == 1)).sum()); tn = int(((gp == 0) & (y == 0)).sum())
        grec = tp / (tp + fn) if tp + fn else 0
        gfpr = fp / (fp + tn) if fp + tn else 0
        print(f"\n=== 워크로드 그룹 CV (임계값 {thr}) ===")
        print(f"  탐지율 {grec:.1%}  오탐률 {gfpr:.1%}  (오탐 {fp}, 미탐 {fn})")
        report["group_cv"] = {"threshold": thr, "recall": grec, "fpr": gfpr,
                              "fp": fp, "fn": fn}

    # 3) Leave-One-Family-Out (악성 패밀리 일반화)
    if "family" in df.columns:
        fams = sorted(set(df.loc[df.label == 1, "family"]) - {""})
        if len(fams) >= 2:
            print("\n=== Leave-One-Family-Out (처음 보는 패밀리) ===")
            lofo = {}
            for fam in fams:
                te = (df.label == 1) & (df.family == fam)
                tr_mask = ~te  # 그 패밀리 악성만 학습에서 제외
                clf = rf().fit(X[tr_mask.to_numpy()], y[tr_mask.to_numpy()])
                thr = best if best is not None else 0.5
                p = clf.predict_proba(X[te.to_numpy()])[:, 1]
                det = float((p >= thr).mean()) if len(p) else 0.0
                lofo[fam] = {"n": int(te.sum()), "detect": round(det, 3)}
                print(f"  {fam:14} {int(te.sum()):2d}개  탐지 {det:.0%}")
            report["lofo"] = lofo

    # 최종 모델 저장. DataFrame으로 fit해 feature_names_in_ 을 남긴다
    # (런타임 load_models 의 피처 일치 검증 + sklearn 경고 방지).
    Xdf = df[FEATURE_ORDER_V5].astype(float)
    model = rf().fit(Xdf, y)
    joblib.dump(model, args.out_model)
    with open(args.out_cols, "w", encoding="utf-8") as f:
        json.dump(FEATURE_ORDER_V5, f, ensure_ascii=False, indent=2)
    os.makedirs(os.path.dirname(args.report), exist_ok=True)
    with open(args.report, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    # 자가진단: 저장 직후 되불러 predict_proba 범위 확인(버전 깨짐 탐지)
    import joblib as _jl
    m2 = _jl.load(args.out_model)
    p = m2.predict_proba(Xdf.iloc[:5])[:, 1]
    ok = (0.0 <= p.min()) and (p.max() <= 1.0)
    print(f"\n[train] 저장: {args.out_model}")
    print(f"[train] 피처목록: {args.out_cols} ({len(FEATURE_ORDER_V5)}개)")
    print(f"[train] 리포트: {args.report}")
    print(f"[train] 로드 자가진단 predict_proba 범위 {'정상' if ok else '비정상(버전 확인!)'} "
          f"(min {p.min():.3f}, max {p.max():.3f})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
