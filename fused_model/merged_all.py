import pandas as pd
import os

# ===============================
# 경로 설정
# ===============================
byte_opcode_csv = (
    "/home/osulg/capstone/Result/merged_ngram/merged_byte300_opcode500.csv"
)
elf_csv = "/home/osulg/capstone/Result/ELF header/elf_header_features.csv"

save_csv = "/home/osulg/capstone/Result/final_merged_all_features.csv"

# ===============================
# CSV 로드
# ===============================
ngram_df = pd.read_csv(byte_opcode_csv)
elf_df = pd.read_csv(elf_csv)

# ===============================
# ELF 불필요 컬럼 제거 (중복 방지)
# ===============================
elf_df = elf_df.drop(columns=["family", "label"])

# ===============================
# merge
# ===============================
final_df = pd.merge(ngram_df, elf_df, on="file_path", how="inner")

# ===============================
# 저장
# ===============================
os.makedirs(os.path.dirname(save_csv), exist_ok=True)
final_df.to_csv(save_csv, index=False)

# ===============================
# 결과 확인
# ===============================
print("\n===== FINAL MERGE COMPLETE =====")
print(f"샘플 수: {len(final_df)}")
print(f"전체 컬럼 수: {final_df.shape[1]}")
print(f"feature 수: {final_df.shape[1] - 3}")  # file_path, family, label 제외

print("\n[label 분포]")
print(final_df["label"].value_counts())

print("\n[family 분포]")
print(final_df["family"].value_counts())
