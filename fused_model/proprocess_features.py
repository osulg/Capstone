import pandas as pd
import os

# ===============================
# 경로 설정
# ===============================
input_csv = "/home/osulg/capstone/Result/final_merged_all_features.csv"
output_csv = "/home/osulg/capstone/Result/preprocessed_features.csv"

# ===============================
# CSV 로드
# ===============================
df = pd.read_csv(input_csv)

print("\n===== BEFORE PREPROCESSING =====")
print("shape:", df.shape)
print("\n[object columns]")
print(df.select_dtypes(include="object").columns.tolist())
print("\n[null counts]")
print(df.isnull().sum()[df.isnull().sum() > 0].sort_values(ascending=False))

# ===============================
# 1. 메타 컬럼 따로 보관
# ===============================
meta_cols = [col for col in ["file_path", "family", "label"] if col in df.columns]
meta_df = df[meta_cols].copy()

# ===============================
# 2. 불필요 컬럼 제거
# ===============================
drop_cols = ["file_name", "parse_error"]
drop_cols = [col for col in drop_cols if col in df.columns]

# feature 후보만 남기기
feature_df = df.drop(columns=drop_cols, errors="ignore")

# 메타 컬럼은 feature에서 제외
feature_df = feature_df.drop(
    columns=[
        col for col in ["file_path", "family", "label"] if col in feature_df.columns
    ],
    errors="ignore",
)

# ===============================
# 3. 결측치 처리
# ===============================
feature_df = feature_df.fillna(0)

# ===============================
# 4. 문자열 컬럼 원-핫 인코딩
# ===============================
feature_df = pd.get_dummies(feature_df)

# ===============================
# 5. 메타 컬럼 다시 붙이기
# ===============================
df_final = pd.concat([meta_df, feature_df], axis=1)

# ===============================
# 결과 저장
# ===============================
os.makedirs(os.path.dirname(output_csv), exist_ok=True)
df_final.to_csv(output_csv, index=False)

# ===============================
# 결과 확인
# ===============================
print("\n===== AFTER PREPROCESSING =====")
print("shape:", df_final.shape)

print("\n[data types]")
print(df_final.dtypes.value_counts())

print("\n[null counts after]")
print(df_final.isnull().sum().sum())

print("\n[first 20 columns]")
print(df_final.columns[:20].tolist())

print("\n[meta columns check]")
print("file_path in columns:", "file_path" in df_final.columns)
print("family in columns   :", "family" in df_final.columns)
print("label in columns    :", "label" in df_final.columns)

print(f"\n저장 완료: {output_csv}")
