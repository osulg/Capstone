import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_validate

# ===============================
# CSV 경로
# ===============================
csv_files = {
    "byte_n3_k300": "/home/osulg/capstone/Result/byte_ngram/byte_ngram_n3_k300_all_dataset.csv",
    "opcode_n3_k500": "/home/osulg/capstone/Result/opcode_ngram/opcode_ngram_n3_k500_all_dataset.csv",
    "merged_byte300_opcode500": "/home/osulg/capstone/Result/merged_ngram/merged_byte300_opcode500.csv",
}

results = []

for exp_name, csv_path in csv_files.items():
    print(f"\n==============================")
    print(f"CV TEST: {exp_name}")
    print(f"==============================")

    # 1) CSV 읽기
    df = pd.read_csv(csv_path)

    # 2) family별 샘플 수 확인
    family_counts = df["family"].value_counts()
    valid_families = family_counts[family_counts >= 3].index

    # 3) 샘플 3개 이상 family만 사용
    df = df[df["family"].isin(valid_families)].copy()

    print("[family counts]")
    print(family_counts.to_string())
    print("\n[valid families (>=3)]")
    print(list(valid_families))
    print(f"\n[filtered samples] {len(df)}")

    if len(df) < 6:
        print("[skip] filtering 후 데이터가 너무 적습니다.")
        continue

    # 4) feature / label 분리
    drop_cols = [col for col in ["file_path", "family", "label"] if col in df.columns]
    X = df.drop(columns=drop_cols)
    y = df["label"]

    print(f"[num_features] {X.shape[1]}")
    print(f"[num_classes] {y.nunique()}")

    # 5) 모델
    model = RandomForestClassifier(
        n_estimators=200, random_state=42, class_weight="balanced"
    )

    # 6) CV
    cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)

    scoring = {
        "accuracy": "accuracy",
        "precision": "precision_macro",
        "recall": "recall_macro",
        "f1": "f1_macro",
    }

    scores = cross_validate(
        model, X, y, cv=cv, scoring=scoring, return_train_score=False
    )

    # 7) 평균/표준편차
    acc_mean = scores["test_accuracy"].mean()
    prec_mean = scores["test_precision"].mean()
    rec_mean = scores["test_recall"].mean()
    f1_mean = scores["test_f1"].mean()

    acc_std = scores["test_accuracy"].std()
    prec_std = scores["test_precision"].std()
    rec_std = scores["test_recall"].std()
    f1_std = scores["test_f1"].std()

    print(f"accuracy : {acc_mean:.4f} ± {acc_std:.4f}")
    print(f"precision: {prec_mean:.4f} ± {prec_std:.4f}")
    print(f"recall   : {rec_mean:.4f} ± {rec_std:.4f}")
    print(f"f1-score : {f1_mean:.4f} ± {f1_std:.4f}")

    results.append(
        [
            exp_name,
            len(df),
            X.shape[1],
            y.nunique(),
            acc_mean,
            acc_std,
            prec_mean,
            prec_std,
            rec_mean,
            rec_std,
            f1_mean,
            f1_std,
        ]
    )

# ===============================
# 최종 결과 표
# ===============================
result_df = pd.DataFrame(
    results,
    columns=[
        "experiment",
        "num_samples",
        "num_features",
        "num_classes",
        "accuracy_mean",
        "accuracy_std",
        "precision_mean",
        "precision_std",
        "recall_mean",
        "recall_std",
        "f1_mean",
        "f1_std",
    ],
)

result_df = result_df.sort_values(by="f1_mean", ascending=False)

print("\n===== FINAL CV RESULT TABLE =====")
print(result_df.to_string(index=False))
