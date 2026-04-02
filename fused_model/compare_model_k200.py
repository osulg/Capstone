# ==============================
# compare_models_k200.py
# ==============================

import pandas as pd
import numpy as np
import os

from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import make_scorer, precision_score, recall_score, f1_score

input_csv = "/home/osulg/capstone/Result/merged_topk_balanced_k200.csv"
save_csv = "/home/osulg/capstone/Result/model_compare_k200.csv"

# ------------------------------
# 0. optional import
# ------------------------------
xgb_available = True
lgbm_available = True

try:
    from xgboost import XGBClassifier
except ImportError:
    xgb_available = False
    print("[INFO] xgboost 설치 안 됨 -> XGBoost 비교 제외")

try:
    from lightgbm import LGBMClassifier
except ImportError:
    lgbm_available = False
    print("[INFO] lightgbm 설치 안 됨 -> LightGBM 비교 제외")


# ------------------------------
# 1. 데이터 로드
# ------------------------------
df = pd.read_csv(input_csv)

meta_cols = [c for c in ["file_path", "family", "label"] if c in df.columns]
X = df.drop(columns=meta_cols, errors="ignore")
y = df["label"]

print("\n===== LOAD DATA =====")
print("shape:", df.shape)
print("X shape:", X.shape)
print("y distribution:")
print(y.value_counts())


# ------------------------------
# 2. CV 설정
# ------------------------------
skf = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)


# ------------------------------
# 3. 평가 지표
# ------------------------------
scoring = {
    "accuracy": "accuracy",
    "precision": make_scorer(precision_score, zero_division=0),
    "recall": make_scorer(recall_score, zero_division=0),
    "f1": make_scorer(f1_score, zero_division=0),
}


# ------------------------------
# 4. 모델 정의
# ------------------------------
models = {
    "RandomForest": RandomForestClassifier(
        n_estimators=200, random_state=42, n_jobs=-1, class_weight="balanced"
    ),
    "LogisticRegression": Pipeline(
        [
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=3000, random_state=42)),
        ]
    ),
    "GradientBoosting": GradientBoostingClassifier(n_estimators=200, random_state=42),
}

if xgb_available:
    models["XGBoost"] = XGBClassifier(
        n_estimators=200, random_state=42, eval_metric="logloss", n_jobs=-1
    )

if lgbm_available:
    models["LightGBM"] = LGBMClassifier(
        n_estimators=100,
        max_depth=4,
        num_leaves=15,
        min_data_in_leaf=5,
        learning_rate=0.05,
        random_state=42,
        n_jobs=-1,
        verbose=-1,
    )


# ------------------------------
# 5. 모델 비교
# ------------------------------
results = []

for name, model in models.items():
    print(f"\n===== {name} =====")

    try:
        scores = cross_validate(
            model, X, y, cv=skf, scoring=scoring, n_jobs=-1, error_score="raise"
        )

        row = {
            "model": name,
            "accuracy_mean": np.mean(scores["test_accuracy"]),
            "accuracy_std": np.std(scores["test_accuracy"]),
            "precision_mean": np.mean(scores["test_precision"]),
            "precision_std": np.std(scores["test_precision"]),
            "recall_mean": np.mean(scores["test_recall"]),
            "recall_std": np.std(scores["test_recall"]),
            "f1_mean": np.mean(scores["test_f1"]),
            "f1_std": np.std(scores["test_f1"]),
        }
        results.append(row)

        print(f'accuracy : {row["accuracy_mean"]:.4f} ± {row["accuracy_std"]:.4f}')
        print(f'precision: {row["precision_mean"]:.4f} ± {row["precision_std"]:.4f}')
        print(f'recall   : {row["recall_mean"]:.4f} ± {row["recall_std"]:.4f}')
        print(f'f1-score : {row["f1_mean"]:.4f} ± {row["f1_std"]:.4f}')

    except Exception as e:
        print(f"[ERROR] {name} 실행 실패: {e}")


# ------------------------------
# 6. 저장
# ------------------------------
result_df = pd.DataFrame(results)

if len(result_df) == 0:
    print("\n[ERROR] 비교 가능한 모델이 없습니다.")
else:
    result_df = result_df.sort_values(by="f1_mean", ascending=False)

    print("\n===== FINAL MODEL COMPARISON =====")
    print(result_df)

    os.makedirs(os.path.dirname(save_csv), exist_ok=True)
    result_df.to_csv(save_csv, index=False)
    print(f"\n저장 완료: {save_csv}")
