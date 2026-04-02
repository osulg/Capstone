# ==============================
# merged_topk_balanced.py
# ==============================

import pandas as pd
import numpy as np
import os

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

input_csv = "/home/osulg/capstone/Result/preprocessed_no_duplicates.csv"
save_csv = "/home/osulg/capstone/Result/merged_topk_balanced_results.csv"

# ==============================
# 1. 데이터 로드
# ==============================
df = pd.read_csv(input_csv)

meta_cols = [c for c in ["file_path", "family", "label"] if c in df.columns]

X = df.drop(columns=meta_cols, errors="ignore")
y = df["label"]

print("\n===== LOAD DATA =====")
print("shape:", df.shape)
print("X shape:", X.shape)
print("y shape:", y.shape)
print("\n[label distribution]")
print(y.value_counts())

# ==============================
# 2. feature 그룹 분리
# ==============================
byte_cols = [c for c in X.columns if c.startswith("byte_f_")]
opcode_cols = [c for c in X.columns if c.startswith("opcode_f_")]
elf_cols = [c for c in X.columns if c not in byte_cols + opcode_cols]

print("BYTE  :", len(byte_cols))
print("OPCODE:", len(opcode_cols))
print("ELF   :", len(elf_cols))

# ==============================
# 3. CV 설정
# ==============================
skf = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)


# ==============================
# 4. importance 계산 함수
# ==============================
def get_sorted_features(X_tr, y_tr, cols):
    if len(cols) == 0:
        return np.array([])

    model = RandomForestClassifier(
        n_estimators=200, random_state=42, n_jobs=-1, class_weight="balanced"
    )
    model.fit(X_tr[cols], y_tr)
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    return np.array(cols)[indices]


# ==============================
# 5. k 분배 보정 함수
# ==============================
def allocate_k_by_ratio(k, ratio, n_elf, n_byte, n_opcode):
    elf_ratio, byte_ratio, opcode_ratio = ratio

    elf_k = int(k * elf_ratio)
    byte_k = int(k * byte_ratio)
    opcode_k = k - elf_k - byte_k

    # 1차: 각 그룹 최대 개수 제한
    elf_k = min(elf_k, n_elf)
    byte_k = min(byte_k, n_byte)
    opcode_k = min(opcode_k, n_opcode)

    # 남는 개수 재분배
    assigned = elf_k + byte_k + opcode_k
    remain = min(k, n_elf + n_byte + n_opcode) - assigned

    capacities = {
        "elf": n_elf - elf_k,
        "byte": n_byte - byte_k,
        "opcode": n_opcode - opcode_k,
    }

    order = ["elf", "byte", "opcode"]
    while remain > 0:
        updated = False
        for name in order:
            if capacities[name] > 0 and remain > 0:
                if name == "elf":
                    elf_k += 1
                elif name == "byte":
                    byte_k += 1
                else:
                    opcode_k += 1
                capacities[name] -= 1
                remain -= 1
                updated = True
        if not updated:
            break

    return elf_k, byte_k, opcode_k


# ==============================
# 6. balanced 실험 함수
# ==============================
def run_balanced_cv(k, ratio=(0.2, 0.4, 0.4)):
    print(f"\n===== balanced_k{k} =====")

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

        # ------------------------------
        # fold 안에서 importance 계산
        # ------------------------------
        byte_sorted = get_sorted_features(X_train, y_train, byte_cols)
        opcode_sorted = get_sorted_features(X_train, y_train, opcode_cols)
        elf_sorted = get_sorted_features(X_train, y_train, elf_cols)

        # ------------------------------
        # k 분배
        # ------------------------------
        max_total_features = len(byte_cols) + len(opcode_cols) + len(elf_cols)
        current_k = min(k, max_total_features)

        elf_k, byte_k, opcode_k = allocate_k_by_ratio(
            current_k,
            ratio,
            len(elf_sorted),
            len(byte_sorted),
            len(opcode_sorted),
        )

        elf_top = list(elf_sorted[:elf_k])
        byte_top = list(byte_sorted[:byte_k])
        opcode_top = list(opcode_sorted[:opcode_k])

        selected_features = elf_top + byte_top + opcode_top

        print(f"[split] ELF:{elf_k}, BYTE:{byte_k}, OPCODE:{opcode_k}")
        print(f"[selected total] {len(selected_features)}")

        # ------------------------------
        # 모델 학습
        # ------------------------------
        model = RandomForestClassifier(
            n_estimators=200, random_state=42, n_jobs=-1, class_weight="balanced"
        )
        model.fit(X_train[selected_features], y_train)

        y_pred = model.predict(X_test[selected_features])

        # ------------------------------
        # 성능
        # ------------------------------
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)

        print(f"accuracy : {acc:.4f}")
        print(f"precision: {prec:.4f}")
        print(f"recall   : {rec:.4f}")
        print(f"f1-score : {f1:.4f}")

        acc_scores.append(acc)
        prec_scores.append(prec)
        rec_scores.append(rec)
        f1_scores.append(f1)

    return {
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


# ==============================
# 7. 실행
# ==============================
k_list = [100, 200, 300]
results = []

for k in k_list:
    results.append(run_balanced_cv(k))

# ==============================
# 8. 저장
# ==============================
result_df = pd.DataFrame(results)
result_df = result_df.sort_values(by="f1_score_mean", ascending=False)

print("\n===== FINAL RESULT =====")
print(result_df)

os.makedirs(os.path.dirname(save_csv), exist_ok=True)
result_df.to_csv(save_csv, index=False)

print(f"\n저장 완료: {save_csv}")
