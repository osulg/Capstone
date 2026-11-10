#!/usr/bin/env python3
"""
동적 모델 v6 평가 (FUSE-only · PID 단위 · 확장자 판정 v6 규칙).

입력 : dataset_v6/ 의 피처 CSV (extract_perpid_fuse.py --workload-only --ext-rule v6 결과)
출력 : 계열 단위 평가, 임계값 표, 상위 피처, (옵션) holdout 1회 평가

평가 원칙:
  - 악성은 "계열" 단위로 묶어 학습/검증에 섞이지 않게 한다(같은 빌더 계열의 근접 중복 방지).
  - 정상은 워크로드 단위로 묶는다(처음 보는 정상 작업에 대한 오탐을 본다).
  - 정상 PID는 파일당 프로세스를 띄우는 워크로드(openssl 등)에 쏠려 있으므로
    run마다 정상 가중치 합이 같도록 맞추고, 정상/악성 가중치 합도 같게 한다.
  - holdout(INCRansom, RansomEXX)은 --holdout 을 줄 때만, 마지막에 한 번 평가한다.

사용:
  python3 models/dynamic/collect/eval_v6.py --data models/dynamic/dataset_v6
  python3 models/dynamic/collect/eval_v6.py --data models/dynamic/dataset_v6 --holdout
"""
import argparse
import os
import sys
import warnings

warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from extract_perpid_fuse import FEATURE_ORDER_V5 as FEATURES  # noqa: E402

# 공개 보고(Monti←Conti, Buhti Linux←Babuk)와 수집 관찰(BrainCipher의 Babuk 동일 패턴)에 근거한 계열
LINEAGE = {"babuk": "babuk", "braincipher": "babuk", "buhti": "babuk",
           "conti": "conti", "monti": "conti"}
# 라벨 신뢰가 낮아 학습에서 제외 (malware_runs.csv의 result=보류)
EXCLUDE_FAMILIES = {"moneymessage"}


def rf(seed=42):
    from sklearn.ensemble import RandomForestClassifier
    return RandomForestClassifier(n_estimators=400, random_state=seed, n_jobs=-1)


def run_balanced_weights(df):
    w = np.ones(len(df))
    b = (df.label == 0).to_numpy()
    w[b] = 1.0 / df[b].groupby("run_id").run_id.transform("count").to_numpy()
    w[b] *= b.sum() / w[b].sum()
    w[~b] *= w[b].sum() / max(1, (~b).sum())
    return w


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=os.path.join(HERE, "..", "dataset_v6"))
    ap.add_argument("--threshold", type=float, default=0.6)
    ap.add_argument("--holdout", action="store_true",
                    help="holdout 1회 평가 (모델·임계값 확정 후에만)")
    args = ap.parse_args()

    from sklearn.model_selection import StratifiedGroupKFold

    ben = pd.read_csv(os.path.join(args.data, "features_benign_v6.csv"))
    mal = pd.read_csv(os.path.join(args.data, "features_malware_train_v6.csv"))
    mal = mal[~mal.family.isin(EXCLUDE_FAMILIES)]
    df = pd.concat([ben, mal], ignore_index=True)
    df["lineage"] = np.where(df.label == 1, df.family.map(lambda f: LINEAGE.get(f, f)), "")
    df["group"] = np.where(df.label == 1, "m_" + df.lineage, "b_" + df.workload)
    X, y = df[FEATURES].to_numpy(float), df.label.to_numpy(int)
    thr = args.threshold
    print(f"정상 PID {int((y == 0).sum())} (run {df[y == 0].run_id.nunique()}) / "
          f"악성 PID {int((y == 1).sum())}  임계값 {thr}")

    print("\n=== Leave-One-Lineage-Out ===")
    lolo = []
    for lin in sorted(df.lineage[df.label == 1].unique()):
        te = ((df.label == 1) & (df.lineage == lin)).to_numpy()
        m = rf().fit(X[~te], y[~te], sample_weight=run_balanced_weights(df[~te]))
        p = m.predict_proba(X[te])[:, 1]
        lolo.extend(p)
        print(f"  {lin:12} {(p >= thr).sum()}/{te.sum()}  점수 {np.round(np.sort(p), 2)}")
    lolo = np.array(lolo)

    print("\n=== 계열·워크로드 그룹 5-fold (분할 3회) ===")
    oofs = []
    for s in (0, 1, 2):
        oof = np.zeros(len(df))
        for tr, te in StratifiedGroupKFold(5, shuffle=True, random_state=s).split(X, y, df.group):
            m = rf(s).fit(X[tr], y[tr], sample_weight=run_balanced_weights(df.iloc[tr]))
            oof[te] = m.predict_proba(X[te])[:, 1]
        oofs.append(oof)
    print("  thr  | 탐지(평균)  오탐 run(평균) | LOLO 탐지")
    for t in (0.5, 0.55, 0.6, 0.65, 0.7):
        det = np.mean([((o >= t) & (y == 1)).sum() for o in oofs])
        fr = np.mean([df[(o >= t) & (y == 0)].run_id.nunique() for o in oofs])
        print(f"  {t:.2f} | {det:5.1f}/{(y == 1).sum()}  {fr:4.1f}/{df[y == 0].run_id.nunique()} "
              f"| {(lolo >= t).sum()}/{len(lolo)}")
    mean_oof = np.mean(oofs, 0)
    b = df[y == 0].assign(p=mean_oof[y == 0])
    top = b.groupby("workload").p.max().sort_values(ascending=False).head(5)
    print("  정상 워크로드별 최고 점수:", ", ".join(f"{w} {v:.2f}" for w, v in top.items()))

    w = run_balanced_weights(df)
    final = rf().fit(X, y, sample_weight=w)
    print("\n=== 상위 피처 (전체 train, run 균형 가중치) ===")
    for f, v in sorted(zip(FEATURES, final.feature_importances_), key=lambda t: -t[1])[:10]:
        print(f"  {f:28} {v:.3f}")

    if args.holdout:
        ho = pd.read_csv(os.path.join(args.data, "features_malware_holdout_v6.csv"))
        p = final.predict_proba(ho[FEATURES].to_numpy(float))[:, 1]
        print(f"\n=== holdout (임계값 {thr}) ===")
        for r, v in zip(ho.run_id, p):
            print(f"  {r:26} {v:.3f}  {'탐지' if v >= thr else '미탐'}")
        print(f"  합계 {(p >= thr).sum()}/{len(p)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
