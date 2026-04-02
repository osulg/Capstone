import pandas as pd
import os

# ===============================
# 경로 설정
# ===============================
byte_csv = "/home/osulg/capstone/Result/byte_ngram/byte_ngram_n3_k300_all_dataset.csv"
opcode_csv = (
    "/home/osulg/capstone/Result/opcode_ngram/opcode_ngram_n3_k500_all_dataset.csv"
)
save_csv = "/home/osulg/capstone/Result/merged_ngram/merged_byte300_opcode500.csv"

# ===============================
# CSV 로드
# ===============================
byte_df = pd.read_csv(byte_csv)
opcode_df = pd.read_csv(opcode_csv)

# ===============================
# 메타 컬럼
# ===============================
meta_cols = ["file_path", "family", "label"]

# ===============================
# 🔥 핵심 1: prefix 붙이기 (여기가 제일 중요)
# ===============================
byte_df = byte_df.rename(
    columns={c: f"byte_{c}" for c in byte_df.columns if c.startswith("f_")}
)

opcode_df = opcode_df.rename(
    columns={c: f"opcode_{c}" for c in opcode_df.columns if c.startswith("f_")}
)

# ===============================
# 🔥 핵심 2: 중복 및 정합성 체크
# ===============================
assert not byte_df["file_path"].duplicated().any(), "byte 중복 있음"
assert not opcode_df["file_path"].duplicated().any(), "opcode 중복 있음"

# ===============================
# 🔥 핵심 3: merge
# ===============================
merged_df = pd.merge(byte_df, opcode_df, on=meta_cols, how="inner")

# ===============================
# 저장
# ===============================
os.makedirs(os.path.dirname(save_csv), exist_ok=True)
merged_df.to_csv(save_csv, index=False)

# ===============================
# 결과 확인
# ===============================
print("\n===== MERGE COMPLETE =====")
print(f"샘플 수: {len(merged_df)}")
print(f"전체 컬럼 수: {merged_df.shape[1]}")
print(f"feature 수: {merged_df.shape[1] - 3}")

# prefix 확인 (디버깅 핵심)
print("\n[컬럼 샘플]")
print([c for c in merged_df.columns if "byte_" in c][:5])
print([c for c in merged_df.columns if "opcode_" in c][:5])

print("\n[label 분포]")
print(merged_df["label"].value_counts())

print("\n[family 분포]")
print(merged_df["family"].value_counts())
