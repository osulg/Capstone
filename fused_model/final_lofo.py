# evaluate_lofo_balanced_k200.py

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
import os

input_csv = "/home/osulg/capstone/Result/k200_with_family.csv"
save_path = "/home/osulg/capstone/Result/evaluation/final_lofo.csv"

print("\n==============================")
print("LOFO TEST: balanced_k200")
print("==============================")

df = pd.read_csv(input_csv)

# family 결측 제거
df = df.dropna(subset=["family"]).copy()

# 문자열 처리 안전하게
df["family"] = df["family"].astype(str)

family_counts = df["family"].value_counts()
candidate_families = [
    fam for fam, cnt in family_counts.items() if fam.lower() != "benign" and cnt >= 3
]

print("=== Candidate malware families for LOFO ===")
print(candidate_families)

results = []

for held_out_family in candidate_families:
    print(f"\n===== HELD-OUT FAMILY: {held_out_family} =====")

    df_test_mal = df[df["family"] == held_out_family].copy()
    df_benign = df[df["family"].str.lower() == "benign"].copy()
    df_train_mal = df[
        (df["family"].str.lower() != "benign") & (df["family"] != held_out_family)
    ].copy()

    if len(df_test_mal) == 0 or len(df_benign) < 2 or len(df_train_mal) == 0:
        print("skip: 데이터 수 부족")
        continue

    test_benign_size = min(len(df_test_mal), len(df_benign) // 2)

    if test_benign_size == 0:
        print("skip: test benign size = 0")
        continue

    df_benign_train, df_benign_test = train_test_split(
        df_benign, test_size=test_benign_size, random_state=42, shuffle=True
    )

    df_train = pd.concat([df_train_mal, df_benign_train], ignore_index=True)
    df_test = pd.concat([df_test_mal, df_benign_test], ignore_index=True)

    drop_cols = [col for col in ["file_path", "family", "label"] if col in df.columns]

    X_train = df_train.drop(columns=drop_cols)
    y_train = df_train["label"]

    X_test = df_test.drop(columns=drop_cols)
    y_test = df_test["label"]

    model = RandomForestClassifier(
        n_estimators=200, random_state=42, class_weight="balanced", n_jobs=-1
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    print(f"train malware: {len(df_train_mal)}")
    print(f"test malware : {len(df_test_mal)}")
    print(f"train benign : {len(df_benign_train)}")
    print(f"test benign  : {len(df_benign_test)}")
    print(f"accuracy : {acc:.4f}")
    print(f"precision: {prec:.4f}")
    print(f"recall   : {rec:.4f}")
    print(f"f1-score : {f1:.4f}")

    results.append(
        [
            held_out_family,
            len(df_train_mal),
            len(df_test_mal),
            len(df_benign_train),
            len(df_benign_test),
            acc,
            prec,
            rec,
            f1,
        ]
    )

result_df = pd.DataFrame(
    results,
    columns=[
        "held_out_family",
        "train_malware",
        "test_malware",
        "train_benign",
        "test_benign",
        "accuracy",
        "precision",
        "recall",
        "f1",
    ],
)

print("\n===== FINAL LOFO RESULT TABLE =====")
print(result_df.to_string(index=False))

print("\n===== AVERAGE LOFO PERFORMANCE =====")
print(result_df[["accuracy", "precision", "recall", "f1"]].mean().to_string())

result_df.to_csv(save_path, index=False)
print(f"\n[saved] {save_path}")
