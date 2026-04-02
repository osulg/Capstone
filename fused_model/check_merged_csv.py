import pandas as pd

# ===============================
# CSV 로드
# ===============================
df = pd.read_csv("/home/osulg/capstone/Result/final_merged_all_features.csv")

print("\n===== BASIC INFO =====")
print("shape:", df.shape)

print("\n===== COLUMNS =====")
print(df.columns[:20])  # 앞 20개만 확인

print("\n===== LABEL DISTRIBUTION =====")
print(df["label"].value_counts())

print("\n===== NULL CHECK =====")
nulls = df.isnull().sum()
print(nulls[nulls > 0].sort_values(ascending=False).head(20))

print("\n===== DATA TYPES =====")
print(df.dtypes.value_counts())

print("\n===== OBJECT COLUMNS =====")
print(df.select_dtypes(include="object").columns.tolist())
