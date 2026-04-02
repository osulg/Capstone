# ==============================
# make_final_k200_dataset.py
# ==============================

import pandas as pd
import numpy as np
import os
from sklearn.ensemble import RandomForestClassifier

input_csv = "/home/osulg/capstone/Result/preprocessed_no_duplicates.csv"
save_csv = "/home/osulg/capstone/Result/merged_topk_balanced_k200.csv"

K = 200
RATIO = (0.2, 0.4, 0.4)  # ELF, BYTE, OPCODE

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
# 3. importance 계산 함수
# ==============================
def get_sorted_features(X_data, y_data, cols):
    if len(cols) == 0:
        return np.array([])

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced"
    )
    model.fit(X_data[cols], y_data)
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    return np.array(cols)[indices]

# ==============================
# 4. k 분배 보정 함수
# ==============================
def allocate_k_by_ratio(k, ratio, n_elf, n_byte, n_opcode):
    elf_ratio, byte_ratio, opcode_ratio = ratio

    elf_k = int(k * elf_ratio)
    byte_k = int(k * byte_ratio)
    opcode_k = k - elf_k - byte_k

    elf_k = min(elf_k, n_elf)
    byte_k = min(byte_k, n_byte)
    opcode_k = min(opcode_k, n_opcode)

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
# 5. 전체 데이터 기준 importance 계산
# ==============================
print("\n===== CALCULATE IMPORTANCE =====")

byte_sorted = get_sorted_features(X, y, byte_cols)
opcode_sorted = get_sorted_features(X, y, opcode_cols)
elf_sorted = get_sorted_features(X, y, elf_cols)

# ==============================
# 6. k 분배
# ==============================
max_total_features = len(byte_sorted) + len(opcode_sorted) + len(elf_sorted)
current_k = min(K, max_total_features)

elf_k, byte_k, opcode_k = allocate_k_by_ratio(
    current_k,
    RATIO,
    len(elf_sorted),
    len(byte_sorted),
    len(opcode_sorted),
)

print(f"\n[split] ELF:{elf_k}, BYTE:{byte_k}, OPCODE:{opcode_k}")

elf_top = list(elf_sorted[:elf_k])
byte_top = list(byte_sorted[:byte_k])
opcode_top = list(opcode_sorted[:opcode_k])

selected_features = elf_top + byte_top + opcode_top

print("\n===== SELECTED FEATURES =====")
print("total:", len(selected_features))
print("sample:", selected_features[:10])

# ==============================
# 7. 최종 데이터셋 생성
# ==============================
# 학습용 k200 데이터셋에는 label만 포함

final_df = df[selected_features + ["label"]].copy()

print("\n===== FINAL DATASET =====")
print("shape:", final_df.shape)

# ==============================
# 8. 저장
# ==============================
os.makedirs(os.path.dirname(save_csv), exist_ok=True)
final_df.to_csv(save_csv, index=False)

print(f"\n저장 완료: {save_csv}")