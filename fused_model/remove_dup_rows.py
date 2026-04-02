import pandas as pd
import os

input_csv = "/home/osulg/capstone/Result/preprocessed_features.csv"
output_csv = "/home/osulg/capstone/Result/preprocessed_no_duplicates.csv"

df = pd.read_csv(input_csv)

print("\n===== BEFORE =====")
print("shape:", df.shape)

# 메타 컬럼 정의
meta_cols = [c for c in ["file_path", "family", "label"] if c in df.columns]

# feature 기준으로만 중복 제거
X = df.drop(columns=meta_cols, errors="ignore")

df_no_dup = df.loc[~X.duplicated()].reset_index(drop=True)

print("\n===== AFTER =====")
print("shape:", df_no_dup.shape)

print("\n제거된 샘플 수:", len(df) - len(df_no_dup))

# sanity check
print("\n[CHECK]")
print("family 존재:", "family" in df_no_dup.columns)
print("file_path 존재:", "file_path" in df_no_dup.columns)

df_no_dup.to_csv(output_csv, index=False)

print(f"\n저장 완료: {output_csv}")
