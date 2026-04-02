import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split

import os

os.makedirs("/home/osulg/capstone/Result/evaluation", exist_ok=True)

csv_files = {
    "byte_n3_k300": "/home/osulg/capstone/Result/byte_ngram/byte_ngram_n3_k300_all_dataset.csv",
    "opcode_n3_k500": "/home/osulg/capstone/Result/opcode_ngram/opcode_ngram_n3_k500_all_dataset.csv",
    "merged_byte300_opcode500": "/home/osulg/capstone/Result/merged_ngram/merged_byte300_opcode500.csv",
}

for exp_name, csv_path in csv_files.items():
    print(f"\n==============================")
    print(f"LOFO TEST: {exp_name}")
    print(f"==============================")

    df = pd.read_csv(csv_path)

    family_counts = df["family"].value_counts()
    candidate_families = [
        fam
        for fam, cnt in family_counts.items()
        if fam.lower() != "benign" and cnt >= 3
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

        test_benign_size = min(len(df_test_mal), len(df_benign) // 2)

        df_benign_train, df_benign_test = train_test_split(
            df_benign, test_size=test_benign_size, random_state=42, shuffle=True
        )

        df_train = pd.concat([df_train_mal, df_benign_train], ignore_index=True)
        df_test = pd.concat([df_test_mal, df_benign_test], ignore_index=True)

        drop_cols = [
            col for col in ["file_path", "family", "label"] if col in df.columns
        ]

        X_train = df_train.drop(columns=drop_cols)
        y_train = df_train["label"]

        X_test = df_test.drop(columns=drop_cols)
        y_test = df_test["label"]

        model = RandomForestClassifier(
            n_estimators=200, random_state=42, class_weight="balanced"
        )
        model.fit(X_train, y_train)

        y_pred = model.predict(X_test)

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)

        print(f"accuracy : {acc:.4f}")
        print(f"precision: {prec:.4f}")
        print(f"recall   : {rec:.4f}")
        print(f"f1-score : {f1:.4f}")

        results.append([held_out_family, acc, prec, rec, f1])

    result_df = pd.DataFrame(
        results, columns=["held_out_family", "accuracy", "precision", "recall", "f1"]
    )

    print(f"\n===== FINAL LOFO RESULT TABLE: {exp_name} =====")
    print(result_df.to_string(index=False))

    print(f"\n===== AVERAGE LOFO PERFORMANCE: {exp_name} =====")
    print(result_df[["accuracy", "precision", "recall", "f1"]].mean().to_string())

    save_path = f"/home/osulg/capstone/Result/evaluation/lofo_{exp_name}.csv"
    result_df.to_csv(save_path, index=False)
    print(f"\n[saved] {save_path}")
