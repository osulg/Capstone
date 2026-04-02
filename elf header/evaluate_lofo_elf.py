import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split

import os

os.makedirs("/home/osulg/capstone/Result/evaluation", exist_ok=True)

csv_files = {
    "elf_header_feature": "/home/osulg/capstone/Result/ELF header/elf_header_features.csv",
}

for exp_name, csv_path in csv_files.items():
    print(f"\n==============================")
    print(f"LOFO TEST: {exp_name}")
    print(f"==============================")

    # 1) CSV 읽기
    df = pd.read_csv(csv_path)

    # 2) 필수 컬럼 확인
    required_cols = ["family", "label"]
    for col in required_cols:
        if col not in df.columns:
            raise ValueError(f"필수 컬럼이 없습니다: {col}")

    # 3) ELF parse 성공 샘플만 사용
    if "elf_parse_ok" in df.columns:
        before = len(df)
        df = df[df["elf_parse_ok"] == 1].copy()
        print(f"[elf_parse_ok == 1] {before} -> {len(df)}")

    # 4) family별 개수 확인
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

        # 5) held-out family / benign / train malware 분리
        df_test_mal = df[df["family"] == held_out_family].copy()
        df_benign = df[df["family"].str.lower() == "benign"].copy()
        df_train_mal = df[
            (df["family"].str.lower() != "benign") & (df["family"] != held_out_family)
        ].copy()

        # 6) test benign 크기 맞추기
        test_benign_size = min(len(df_test_mal), len(df_benign) // 2)
        
        if test_benign_size < 1:
            print(f"[skip] benign test size가 0이라 {held_out_family}는 건너뜁니다.")
            continue

        df_benign_train, df_benign_test = train_test_split(
            df_benign, test_size=test_benign_size, random_state=42, shuffle=True
        )

        df_train = pd.concat([df_train_mal, df_benign_train], ignore_index=True)
        df_test = pd.concat([df_test_mal, df_benign_test], ignore_index=True)

        # 7) feature / label 분리
        drop_cols = [
            col
            for col in ["file_path", "file_name", "family", "label", "parse_error"]
            if col in df.columns
        ]

        X_train = df_train.drop(columns=drop_cols)
        y_train = df_train["label"]

        X_test = df_test.drop(columns=drop_cols)
        y_test = df_test["label"]

        # 8) 문자열(object) 컬럼 제거
        non_numeric_cols = X_train.select_dtypes(include=["object"]).columns.tolist()
        if non_numeric_cols:
            print("[drop object columns]")
            print(non_numeric_cols)
            X_train = X_train.drop(columns=non_numeric_cols)
            X_test = X_test.drop(columns=non_numeric_cols)

        # 9) bool -> int
        bool_cols = X_train.select_dtypes(include=["bool"]).columns.tolist()
        if bool_cols:
            X_train[bool_cols] = X_train[bool_cols].astype(int)
            X_test[bool_cols] = X_test[bool_cols].astype(int)

        # 10) 결측치 처리
        X_train = X_train.fillna(0)
        X_test = X_test.fillna(0)

        print(f"[train samples] {len(df_train)}")
        print(f"[test samples]  {len(df_test)}")
        print(f"[num_features]  {X_train.shape[1]}")
        print("[train label counts]")
        print(y_train.value_counts().to_string())
        print("[test label counts]")
        print(y_test.value_counts().to_string())

        # 11) 모델 학습
        model = RandomForestClassifier(
            n_estimators=200,
            random_state=42,
            class_weight="balanced",
            n_jobs=-1,
        )
        model.fit(X_train, y_train)

        # 12) 예측 및 평가
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

    # 13) 결과 표
    result_df = pd.DataFrame(
        results, columns=["held_out_family", "accuracy", "precision", "recall", "f1"]
    )

    print(f"\n===== FINAL LOFO RESULT TABLE: {exp_name} =====")
    print(result_df.to_string(index=False))

    print(f"\n===== AVERAGE LOFO PERFORMANCE: {exp_name} =====")
    print(result_df[["accuracy", "precision", "recall", "f1"]].mean().to_string())

    # 14) 저장
    save_path = f"/home/osulg/capstone/Result/evaluation/lofo_{exp_name}.csv"
    result_df.to_csv(save_path, index=False)
    print(f"\n[saved] {save_path}")
