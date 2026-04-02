import pandas as pd
import numpy as np
import os

from sklearn.model_selection import StratifiedKFold
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# ===============================
# 경로 설정
# ===============================
input_csv = "/home/osulg/capstone/Result/preprocessed_no_duplicates.csv"
save_csv = "/home/osulg/capstone/Result/k_comparison_results.csv"

# ===============================
# 데이터 로드
# ===============================
df = pd.read_csv(input_csv)

print("\n===== LOAD DATA =====")
print("shape:", df.shape)

# ===============================
# X / y 분리
# meta 컬럼은 feature에서 제외
# ===============================
meta_cols = [c for c in ["file_path", "family", "label"] if c in df.columns]

X = df.drop(columns=meta_cols, errors="ignore")
y = df["label"]

print("\n===== X / y INFO =====")
print("X shape:", X.shape)
print("y shape:", y.shape)
print("\n[label distribution]")
print(y.value_counts())

# ===============================
# CV 설정
# ===============================
skf = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)

# ===============================
# k 값 비교
# ===============================
k_list = [100, 200, 300]
results = []

for k in k_list:
    print(f"\n===== k = {k} =====")

    acc_scores = []
    prec_scores = []
    rec_scores = []
    f1_scores = []

    for fold, (train_idx, test_idx) in enumerate(skf.split(X, y), start=1):
        print(f"\n--- Fold {fold} ---")

        X_train = X.iloc[train_idx]
        X_test = X.iloc[test_idx]
        y_train = y.iloc[train_idx]
        y_test = y.iloc[test_idx]

        # k가 feature 개수보다 크면 자동 조정
        current_k = min(k, X_train.shape[1])

        # feature selection
        selector = SelectKBest(score_func=chi2, k=current_k)
        X_train_selected = selector.fit_transform(X_train, y_train)
        X_test_selected = selector.transform(X_test)

        print("X_train_selected shape:", X_train_selected.shape)
        print("X_test_selected shape :", X_test_selected.shape)

        # model
        model = RandomForestClassifier(
            n_estimators=200, random_state=42, class_weight="balanced", n_jobs=-1
        )
        model.fit(X_train_selected, y_train)

        # predict
        y_pred = model.predict(X_test_selected)

        # metrics
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)

        print("accuracy :", round(acc, 4))
        print("precision:", round(prec, 4))
        print("recall   :", round(rec, 4))
        print("f1-score :", round(f1, 4))

        acc_scores.append(acc)
        prec_scores.append(prec)
        rec_scores.append(rec)
        f1_scores.append(f1)

    results.append(
        {
            "k": k,
            "accuracy_mean": np.mean(acc_scores),
            "accuracy_std": np.std(acc_scores),
            "precision_mean": np.mean(prec_scores),
            "precision_std": np.std(prec_scores),
            "recall_mean": np.mean(rec_scores),
            "recall_std": np.std(rec_scores),
            "f1_score_mean": np.mean(f1_scores),
            "f1_score_std": np.std(f1_scores),
        }
    )

# ===============================
# 결과 정리 및 저장
# ===============================
result_df = pd.DataFrame(results)
result_df = result_df.sort_values(by="f1_score_mean", ascending=False)

print("\n===== FINAL RESULT =====")
print(result_df)

os.makedirs(os.path.dirname(save_csv), exist_ok=True)
result_df.to_csv(save_csv, index=False)

print(f"\n저장 완료: {save_csv}")
