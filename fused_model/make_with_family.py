# make_balanced_k200_with_family.py

import os
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

# ==============================
# 설정
# ==============================
input_csv = "/home/osulg/capstone/Result/preprocessed_no_duplicates.csv"
save_csv = "/home/osulg/capstone/Result/k200_with_family.csv"

K = 200
RATIO = (0.2, 0.4, 0.4)  # (elf, byte, opcode)
RANDOM_STATE = 42

# ==============================
# 1. 데이터 로드
# ==============================
df = pd.read_csv(input_csv)

print("\n===== LOAD DATA =====")
print("shape:", df.shape)

# meta 컬럼
meta_cols = ["file_path", "family", "label"]

# 실제로 존재하는 meta 컬럼만 사용
meta_cols = [c for c in meta_cols if c in df.columns]

# label 체크
if "label" not in df.columns:
    raise ValueError("label 컬럼이 없습니다.")

# family 체크
if "family" not in df.columns:
    raise ValueError(
        "family 컬럼이 없습니다. LOFO를 하려면 family가 반드시 필요합니다."
    )

# file_path는 없어도 되지만 있으면 같이 저장
print("meta_cols:", meta_cols)

# ==============================
# 2. feature / label 분리
# ==============================
X = df.drop(columns=meta_cols)
y = df["label"]

print("feature shape:", X.shape)

# ==============================
# 3. feature 그룹 분리
# ==============================
byte_cols = [c for c in X.columns if c.startswith("byte_f_")]
opcode_cols = [c for c in X.columns if c.startswith("opcode_f_")]
elf_cols = [c for c in X.columns if c not in byte_cols + opcode_cols]

print("\n===== FEATURE GROUPS =====")
print("BYTE  :", len(byte_cols))
print("OPCODE:", len(opcode_cols))
print("ELF   :", len(elf_cols))

# 안전 체크
if len(byte_cols) == 0 or len(opcode_cols) == 0 or len(elf_cols) == 0:
    raise ValueError("feature 그룹 분리가 비정상입니다. 컬럼명을 다시 확인하세요.")


# ==============================
# 4. 중요도 정렬 함수
# ==============================
def get_sorted_features(X_in, y_in, cols):
    if len(cols) == 0:
        return []

    model = RandomForestClassifier(
        n_estimators=300, random_state=RANDOM_STATE, n_jobs=-1
    )
    model.fit(X_in[cols], y_in)

    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    return list(np.array(cols)[indices])


# ==============================
# 5. 그룹별 importance 계산
# ==============================
print("\n===== CALCULATE IMPORTANCE =====")
byte_sorted = get_sorted_features(X, y, byte_cols)
opcode_sorted = get_sorted_features(X, y, opcode_cols)
elf_sorted = get_sorted_features(X, y, elf_cols)

# ==============================
# 6. k 분배
# ==============================
elf_ratio, byte_ratio, opcode_ratio = RATIO

elf_k = int(K * elf_ratio)
byte_k = int(K * byte_ratio)
opcode_k = K - elf_k - byte_k

print("\n===== SPLIT K =====")
print(f"ELF   : {elf_k}")
print(f"BYTE  : {byte_k}")
print(f"OPCODE: {opcode_k}")

# 실제 선택
elf_top = elf_sorted[: min(elf_k, len(elf_sorted))]
byte_top = byte_sorted[: min(byte_k, len(byte_sorted))]
opcode_top = opcode_sorted[: min(opcode_k, len(opcode_sorted))]

selected_features = elf_top + byte_top + opcode_top

print("\n===== SELECTED FEATURES =====")
print("total selected:", len(selected_features))
print("sample:", selected_features[:10])

# 중복 체크
if len(selected_features) != len(set(selected_features)):
    raise ValueError("selected_features에 중복이 있습니다.")

# ==============================
# 7. 최종 CSV 생성
# ==============================
final_cols = meta_cols + selected_features
final_df = df[final_cols].copy()

print("\n===== FINAL DATA =====")
print("shape:", final_df.shape)
print("columns (first 20):", final_df.columns.tolist()[:20])

# family 결측 체크
if "family" in final_df.columns:
    null_family = final_df["family"].isna().sum()
    print("null family:", null_family)

os.makedirs(os.path.dirname(save_csv), exist_ok=True)
final_df.to_csv(save_csv, index=False)

print(f"\n저장 완료: {save_csv}")
