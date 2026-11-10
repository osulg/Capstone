#!/usr/bin/env python3
"""
동적 모델 v6 최종 학습·저장 (FUSE-only · PID 단위 · 확장자 판정 v6 규칙).

평가·임계값 근거는 dataset_v6/RESULTS.md 와 eval_v6.py 참고. 이 스크립트는
그때 확정한 설정(RandomForest 400, random_state=42, run 균형 가중치)으로
train 데이터 전체를 학습해 런타임용 pkl 을 저장한다. holdout 은 쓰지 않는다.

중요: 반드시 GuardFS venv(배포 때와 같은 scikit-learn)에서 실행할 것.
      다른 버전에서 저장하면 런타임 로드시 predict_proba 가 깨진다.
주의: 런타임 PidStats(passthrough.py)가 v6 확장자 규칙으로 맞춰지기 전에는
      paths.py 의 DYNAMIC_MODEL_PATH 를 v6 로 바꾸지 말 것.

사용:
  python3 models/dynamic/collect/train_v6.py
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
from eval_v6 import EXCLUDE_FAMILIES, FEATURES, rf, run_balanced_weights  # noqa: E402

THRESHOLD = 0.6


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=os.path.join(HERE, "..", "dataset_v6"))
    ap.add_argument("--out-model", default=os.path.join(HERE, "..", "rf_model_v6.pkl"))
    ap.add_argument("--out-cols", default=os.path.join(HERE, "..", "feature_cols_v6.json"))
    ap.add_argument("--out-meta", default=os.path.join(HERE, "..", "dataset_v6", "train_v6_meta.json"))
    args = ap.parse_args()

    import joblib
    import sklearn

    ben = pd.read_csv(os.path.join(args.data, "features_benign_v6.csv"))
    mal = pd.read_csv(os.path.join(args.data, "features_malware_train_v6.csv"))
    mal = mal[~mal.family.isin(EXCLUDE_FAMILIES)]
    df = pd.concat([ben, mal], ignore_index=True)
    y = df.label.to_numpy(int)
    w = run_balanced_weights(df)

    # DataFrame으로 fit해 feature_names_in_ 을 남긴다(런타임 피처 일치 검증용, v5와 동일).
    Xdf = df[FEATURES].astype(float)
    model = rf().fit(Xdf, y, sample_weight=w)

    joblib.dump(model, args.out_model)
    with open(args.out_cols, "w", encoding="utf-8") as f:
        json.dump(FEATURES, f, ensure_ascii=False, indent=2)
    meta = {
        "threshold": THRESHOLD,
        "ext_rule": "v6",
        "sklearn": sklearn.__version__,
        "n_benign_pid": int((y == 0).sum()),
        "n_benign_run": int(df[y == 0].run_id.nunique()),
        "n_malware_pid": int((y == 1).sum()),
        "excluded_families": sorted(EXCLUDE_FAMILIES),
        "features": FEATURES,
    }
    with open(args.out_meta, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    # 자가진단: 되불러 predict_proba 범위와 train 적합도 확인(버전 깨짐 탐지)
    m2 = joblib.load(args.out_model)
    p = m2.predict_proba(Xdf)[:, 1]
    ok = bool(np.all((p >= 0.0) & (p <= 1.0)))
    print(f"[train_v6] sklearn {sklearn.__version__}  정상 PID {meta['n_benign_pid']} "
          f"(run {meta['n_benign_run']}) / 악성 PID {meta['n_malware_pid']}")
    print(f"[train_v6] 저장: {args.out_model}")
    print(f"[train_v6] 피처목록: {args.out_cols} ({len(FEATURES)}개)")
    print(f"[train_v6] 메타: {args.out_meta} (임계값 {THRESHOLD})")
    print(f"[train_v6] train 적합: 악성 {int((p[y == 1] >= THRESHOLD).sum())}/{int((y == 1).sum())} 탐지, "
          f"정상 {int((p[y == 0] >= THRESHOLD).sum())}개 오탐 (학습 데이터라 참고용)")
    print(f"[train_v6] 로드 자가진단 predict_proba 범위 {'정상' if ok else '비정상(버전 확인!)'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
