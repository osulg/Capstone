#!/usr/bin/env python3
"""
동적(행동) 모델 단독 HIGH 임계값(STAGE2_DYN_ONLY_HIGH_THRESHOLD)을
데이터로 계산한다.

배경:
  Stage2 fusion은 score = w_d*dyn + w_s*stat 가중합이다. 실행 파일이 양성
  인터프리터(python3 등)인 스크립트형 랜섬웨어는 stat 점수가 낮아 가중합이
  HIGH(0.82)에 영원히 도달 못 한다. 그래서 "dyn 단독으로 충분히 확신하면
  정적 무관하게 HIGH"라는 OR 규칙을 두는데, 그 단독 임계값을 추정으로 박지
  않고 배포 모델의 점수 분포에서 계산한다.

방법:
  1) 배포 모델(rf_model_v2.pkl)을 그대로 쓸 수 있으면(= 같은 sklearn 버전)
     그 모델로 학습 데이터에 in-sample 점수를 매겨 무결성을 확인한다.
  2) 같은 하이퍼파라미터로 5-fold 교차검증 OOF 점수를 내서(처음 보는 데이터
     기준) 정상/악성 점수 분포를 구한다.
  3) 임계값을 스윕해 FPR(정상 오탐)과 탐지율(악성)의 트레이드오프를 출력하고,
     FPR 0%가 되는 최저 임계값과 여유(margin)를 둔 권장값을 제시한다.

중요: sklearn 버전이 모델 학습 버전과 다르면 배포 pkl의 predict_proba가
      확률이 아닌 깨진 값을 낸다(정상 범위 0~1을 벗어남). 이 스크립트는 이를
      감지해 경고하고, pkl 재적합이 불가능하면 '같은 params로 새로 학습'해
      추정만 낸다. 권위 있는 값은 GuardFS venv(배포 때와 같은 sklearn)에서
      실행해야 한다.

사용:
  python3 scripts/calc_dyn_threshold.py          # 기본 경로
  python3 scripts/calc_dyn_threshold.py --csv ... --model ... --cols ...
"""
import argparse
import json
import os
import warnings

warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.realpath(os.path.join(HERE, ".."))


def fresh_rf_like(model):
    """배포 모델에서 핵심 하이퍼파라미터만 뽑아 동일 설정의 새 RF를 만든다.
    (구버전 pkl은 get_params/clone이 monotonic_cst 등에서 실패할 수 있어
     속성을 직접 읽는다.)"""
    from sklearn.ensemble import RandomForestClassifier
    keys = ["n_estimators", "criterion", "max_depth", "min_samples_split",
            "min_samples_leaf", "max_features", "class_weight", "bootstrap",
            "random_state"]
    params = {k: getattr(model, k) for k in keys if hasattr(model, k)}
    params.setdefault("random_state", 42)
    return RandomForestClassifier(**params), params


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=os.path.join(
        REPO, "models/dynamic/dataset_v2/csv/dataset_v2_4th_clean.csv"))
    ap.add_argument("--model", default=os.path.join(
        REPO, "models/dynamic/rf_model_v2.pkl"))
    ap.add_argument("--cols", default=os.path.join(
        REPO, "models/dynamic/feature_cols_v2.json"))
    ap.add_argument("--label-col", default="Label")
    ap.add_argument("--folds", type=int, default=5)
    args = ap.parse_args()

    import joblib
    from sklearn.model_selection import StratifiedKFold

    cols = json.load(open(args.cols))
    df = pd.read_csv(args.csv)
    missing = [c for c in cols if c not in df.columns]
    if missing:
        raise SystemExit(f"[오류] CSV에 피처 컬럼 누락: {missing[:5]} ...")
    X = df[cols].to_numpy(float)
    y = df[args.label_col].to_numpy(int)
    nb, nm = int((y == 0).sum()), int((y == 1).sum())
    print(f"데이터: 정상 {nb} / 악성 {nm}  (피처 {len(cols)}개)")

    model = joblib.load(args.model)
    mal_idx = list(model.classes_).index(1)

    # 1) in-sample 무결성 확인
    pkl_ok = True
    try:
        p_in = model.predict_proba(X)[:, mal_idx]
        if p_in.max() > 1.0001 or p_in.min() < -0.0001:
            pkl_ok = False
            print(f"\n[경고] 배포 pkl predict_proba 범위 이상 "
                  f"(min {p_in.min():.3f}, max {p_in.max():.3f}) "
                  f"— sklearn 버전 불일치로 모델이 깨짐. "
                  f"이 환경 점수는 신뢰 불가. GuardFS venv에서 재실행 필요.")
        else:
            print(f"\n=== in-sample (배포 모델 직접) ===")
            print(f"  정상 dyn 최대 {p_in[y==0].max():.3f} / "
                  f"악성 dyn 최소 {p_in[y==1].min():.3f}")
    except Exception as e:
        pkl_ok = False
        print(f"\n[경고] 배포 pkl 점수 계산 실패: {e}")

    # 2) 교차검증 OOF (항상 새 RF로 재적합 → 버전 깨짐 영향 없음)
    rf, params = fresh_rf_like(model)
    print(f"\n[CV] 재적합 RF 하이퍼파라미터: "
          f"{ {k: params[k] for k in ('n_estimators','max_depth','max_features','class_weight') if k in params} }")
    oof = np.full(len(y), np.nan)
    skf = StratifiedKFold(n_splits=args.folds, shuffle=True, random_state=42)
    from sklearn.ensemble import RandomForestClassifier
    for tr, va in skf.split(X, y):
        clf = RandomForestClassifier(**params)
        clf.fit(X[tr], y[tr])
        oof[va] = clf.predict_proba(X[va])[:, list(clf.classes_).index(1)]

    tag = "배포 모델과 동일 params 재적합" if not pkl_ok else "배포 params 재적합"
    print(f"\n=== {args.folds}-fold 교차검증 OOF ({tag}; 임계값은 이걸로) ===")
    print(f"  정상 dyn: 평균 {oof[y==0].mean():.3f}  최대 {oof[y==0].max():.3f}  "
          f"상위5 {np.sort(oof[y==0])[-5:].round(3)}")
    print(f"  악성 dyn: 평균 {oof[y==1].mean():.3f}  최소 {oof[y==1].min():.3f}  "
          f"하위5 {np.sort(oof[y==1])[:5].round(3)}")

    # 3) 임계값 스윕
    print("\n=== dyn-only 임계값 스윕 (OOF 기준) ===")
    print("  thr     FPR(정상오탐)         탐지율(악성)")
    best = None
    for thr in [round(t, 2) for t in np.arange(0.40, 0.96, 0.05)]:
        fp = int((oof[y == 0] >= thr).sum())
        tp = int((oof[y == 1] >= thr).sum())
        mark = ""
        if fp == 0 and best is None:
            best = thr; mark = "  <- FPR 0% 되는 최저 thr"
        print(f"  {thr:.2f}   {fp/nb:6.1%} ({fp:2d}/{nb})      "
              f"{tp/nm:6.1%} ({tp:2d}/{nm}){mark}")

    ben_max = float(oof[y == 0].max())
    print(f"\n정상 OOF 최대 점수 = {ben_max:.3f}")
    if best is not None:
        rec_at = int((oof[y == 1] >= best).sum())
        margin = round(min(0.95, best + 0.05), 2)
        print(f"→ FPR 0% 보장 최저 임계값 ≈ {best} "
              f"(그때 악성 탐지율 {rec_at}/{nm} = {rec_at/nm:.1%})")
        print(f"→ 여유(margin) 둔 권장값 = {margin}")
    else:
        print("→ 0.95 이하에서 FPR 0% 되는 임계값 없음 "
              "(정상에 고점수 run 존재 — 분리가 약함)")
    if not pkl_ok:
        print("\n⚠ 이 결과는 '새로 학습한 RF' 기준 추정치다. 배포 모델 그대로의"
              "\n  권위 있는 수치는 GuardFS venv(배포 때 sklearn)에서 재실행할 것.")


if __name__ == "__main__":
    main()
