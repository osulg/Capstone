#!/usr/bin/env python3
"""
반지도(이상탐지) 랜섬웨어 탐지 모델 학습 (ELFInsight식 접근).

배경: 오프라인 격리 환경에서 실제로 암호화하는 악성 샘플을 충분히 모으기 어렵다.
      (기존 악성 26개 중 실제 파일 작업을 한 것은 5개뿐 → 이진분류 신뢰 불가)
해법: "정상 행동 분포"만 학습하고, 거기서 벗어나는 것을 이상치로 탐지한다.
      악성 데이터가 부족해도 되고, 잘 모은 정상 데이터가 강점이 된다.

입력: logs_to_csv.py가 만든 피처 CSV (features.py의 24개 행동 피처)
  --benign-csv : 정상 샘플 (학습에 사용)
  --malware-csv: 악성 샘플 (평가에만 사용, 선택). 같은 24피처 스키마여야 함.

방법:
  1) 정상을 워크로드(도구) 단위로 train/val 분할 → val에서 목표 FPR로 임계값 보정
     (같은 워크로드가 train/val에 섞이지 않게 = 현실적 오탐률 평가)
  2) IsolationForest / One-Class SVM / LocalOutlierFactor 를 정상만으로 학습
  3) 보정된 임계값으로 held-out 정상(FPR)과 악성(탐지율) 평가
  4) 규칙 baseline(고엔트로피 write 존재 여부)과 비교
  5) 전체 정상으로 최종 모델 재학습 후 저장

사용 예:
  python3 models/dynamic/collect/train_anomaly.py \
      --benign-csv ~/benign_features.csv \
      --malware-csv ~/malware_features.csv \
      --out ~/anomaly_model.pkl
"""

import argparse
import json
import os
import sys

import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import RobustScaler
from sklearn.model_selection import GroupKFold

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from features import FEATURE_ORDER  # noqa: E402

# 스케일이 큰 카운트/바이트 피처는 log1p로 눌러 극단값(예: sqlite 수천 write) 영향을 줄인다.
LOG_FEATURES = {
    "total_events", "write_per_sec", "unlink_per_sec", "rename_per_sec",
    "create_per_sec", "high_entropy_write_count", "unique_files_touched",
    "unique_dirs_touched", "files_per_dir", "total_write_bytes",
    "mean_write_bytes", "proc_count", "crypto_calls", "distinct_ext_after_rename",
    "duration_sec",
}


def parse_args():
    p = argparse.ArgumentParser(description="반지도 이상탐지 랜섬웨어 탐지 학습")
    p.add_argument("--benign-csv", required=True)
    p.add_argument("--malware-csv", help="평가용 악성 CSV (선택, 같은 피처 스키마)")
    p.add_argument("--target-fpr", type=float, default=0.05,
                   help="정상 검증셋에서 허용할 오탐률로 임계값 보정 (기본 5%)")
    p.add_argument("--folds", type=int, default=5, help="워크로드 그룹 교차검증 fold 수")
    p.add_argument("--out", default="anomaly_model.pkl", help="최종 모델 저장 경로")
    p.add_argument("--report", default="anomaly_report.json")
    return p.parse_args()


def workload_of(run_id: str) -> str:
    """benign_bulk_copy_100x4k_2 → bulk_copy (도구 단위 그룹). 규칙에 안 맞으면 전체 사용."""
    s = str(run_id)
    for prefix in ("benign_", "malware_"):
        if s.startswith(prefix):
            s = s[len(prefix):]
            break
    # 뒤쪽 _<개수>x<크기>k_<반복> 또는 _<해시>_<반복> 제거
    parts = s.split("_")
    # 뒤에서부터 숫자/크기/해시로 보이는 토큰 제거
    while parts and (parts[-1].isdigit()
                     or parts[-1].replace("k", "").replace("x", "").isdigit()
                     or (len(parts[-1]) == 8 and all(c in "0123456789abcdef" for c in parts[-1]))):
        parts.pop()
    return "_".join(parts) or s


def load(path):
    df = pd.read_csv(path)
    missing = [c for c in FEATURE_ORDER if c not in df.columns]
    if missing:
        raise SystemExit(f"[train] {path}: 피처 컬럼 누락 {missing}")
    if "run_id" not in df.columns:
        df["run_id"] = [f"row_{i}" for i in range(len(df))]
    df["workload"] = df["run_id"].map(workload_of)
    return df


def transform(X: pd.DataFrame) -> np.ndarray:
    X = X.copy()
    for c in LOG_FEATURES:
        if c in X.columns:
            X[c] = np.log1p(X[c].clip(lower=0))
    return X[FEATURE_ORDER].to_numpy(dtype=float)


def make_models():
    # 세 가지 이상탐지기. 모두 정상만으로 학습(novelty detection).
    return {
        "IsolationForest": IsolationForest(
            n_estimators=200, contamination="auto", random_state=42),
        "OneClassSVM": OneClassSVM(kernel="rbf", gamma="scale", nu=0.05),
        "LOF": LocalOutlierFactor(n_neighbors=20, novelty=True),
    }


def anomaly_score(model, Xs):
    """값이 클수록 이상(악성)에 가깝도록 부호 통일. score_samples는 클수록 정상이므로 음수화."""
    return -model.score_samples(Xs)


def evaluate(name, ben_df, mal_df, target_fpr, folds):
    """워크로드 그룹 교차검증으로 정상 FPR과 악성 탐지율을 추정."""
    groups = ben_df["workload"].to_numpy()
    Xb = transform(ben_df)
    n_groups = len(set(groups))
    k = min(folds, n_groups)

    gkf = GroupKFold(n_splits=k)
    fpr_list, recall_list = [], []
    Xm = transform(mal_df) if mal_df is not None else None

    for tr, val in gkf.split(Xb, groups=groups):
        scaler = RobustScaler().fit(Xb[tr])
        Xtr, Xval = scaler.transform(Xb[tr]), scaler.transform(Xb[val])

        model = make_models()[name]
        model.fit(Xtr)

        # 학습 정상 점수 분포에서 목표 FPR 분위수로 임계값 설정
        s_tr = anomaly_score(model, Xtr)
        thr = np.quantile(s_tr, 1.0 - target_fpr)

        # held-out 정상 오탐률
        s_val = anomaly_score(model, Xval)
        fpr_list.append(float((s_val > thr).mean()))

        # 악성 탐지율 (있으면)
        if Xm is not None and len(Xm):
            s_mal = scaler.transform(Xm)
            recall_list.append(float((anomaly_score(model, s_mal) > thr).mean()))

    return {
        "held_out_fpr_mean": round(float(np.mean(fpr_list)), 4),
        "held_out_fpr_std": round(float(np.std(fpr_list)), 4),
        "malware_recall_mean": round(float(np.mean(recall_list)), 4) if recall_list else None,
        "malware_recall_std": round(float(np.std(recall_list)), 4) if recall_list else None,
    }


def rule_baseline(mal_df, ben_df):
    """규칙: 고엔트로피 write가 1개 이상이면 악성. 엔트로피 없으면 판단 보류(정상 처리)."""
    def flag(df):
        return (df["high_entropy_write_count"].to_numpy() >= 1).astype(int)
    out = {"benign_fpr": round(float(flag(ben_df).mean()), 4)}
    if mal_df is not None and len(mal_df):
        out["malware_recall"] = round(float(flag(mal_df).mean()), 4)
    return out


def main():
    args = parse_args()
    ben = load(args.benign_csv)
    mal = load(args.malware_csv) if args.malware_csv else None

    print(f"[train] 정상 {len(ben)}개 (워크로드 {ben['workload'].nunique()}종)")
    if mal is not None:
        print(f"[train] 악성 {len(mal)}개 (평가 전용)")
        # 엔트로피 병합이 됐는지 점검 (안 됐으면 핵심 신호가 빔)
        if ben["entropy_available"].mean() < 0.5:
            print("[train] 경고: 정상 샘플의 entropy_available 비율이 낮습니다 "
                  "(FUSE 로그 병합 확인 필요)")

    report = {
        "n_benign": len(ben),
        "n_malware": int(len(mal)) if mal is not None else 0,
        "target_fpr": args.target_fpr,
        "models": {},
        "rule_baseline": rule_baseline(mal, ben),
    }

    print("\n=== 이상탐지 모델별 성능 (워크로드 그룹 교차검증) ===")
    for name in make_models():
        res = evaluate(name, ben, mal, args.target_fpr, args.folds)
        report["models"][name] = res
        rec = res["malware_recall_mean"]
        rec_s = f"악성탐지율 {rec:.1%}" if rec is not None else "악성 평가셋 없음"
        print(f"  {name:16} 오탐률(FPR) {res['held_out_fpr_mean']:.1%} "
              f"±{res['held_out_fpr_std']:.1%}  |  {rec_s}")

    rb = report["rule_baseline"]
    rb_rec = rb.get("malware_recall")
    print(f"\n=== 규칙 baseline (고엔트로피 write>=1) ===")
    print(f"  오탐률 {rb['benign_fpr']:.1%}"
          + (f"  |  악성탐지율 {rb_rec:.1%}" if rb_rec is not None else ""))

    # 전체 정상으로 최종 모델 재학습 후 저장 (IsolationForest 기본)
    import joblib
    scaler = RobustScaler().fit(transform(ben))
    final = IsolationForest(n_estimators=300, contamination="auto", random_state=42)
    final.fit(scaler.transform(transform(ben)))
    thr = float(np.quantile(anomaly_score(final, scaler.transform(transform(ben))),
                            1.0 - args.target_fpr))
    joblib.dump({"model": final, "scaler": scaler, "threshold": thr,
                 "features": FEATURE_ORDER, "log_features": sorted(LOG_FEATURES)},
                args.out)
    print(f"\n[train] 최종 모델 저장: {args.out} (임계값={thr:.4f})")

    with open(args.report, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"[train] 리포트 저장: {args.report}")

    # 해석 가이드
    print("\n=== 해석 ===")
    print("- 오탐률(FPR)이 목표치 근처면 정상 분포 학습이 잘 된 것.")
    print("- 악성탐지율이 낮다면: 그 악성 샘플들이 실제로 암호화를 안 했을 가능성이 큼")
    print("  (행동이 정상과 구분 안 됨). 이는 '실제 동작하는 악성 수집 필요'의 근거가 됨.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
