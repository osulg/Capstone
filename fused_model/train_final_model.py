import os
import pickle
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

# ==============================
# 경로 설정
# ==============================
input_csv = "/home/osulg/capstone/Result/merged_topk_balanced_k200.csv"
save_dir = "/home/osulg/capstone/Result/final_model"

model_path = os.path.join(save_dir, "final_rf_model.pkl")
feature_path = os.path.join(save_dir, "selected_features.pkl")

os.makedirs(save_dir, exist_ok=True)

# ==============================
# 1. 데이터 로드
# ==============================
df = pd.read_csv(input_csv)

print("===== LOAD DATA =====")
print("shape:", df.shape)
print("columns:", df.columns.tolist()[:10], "...")

# ==============================
# 2. meta / feature 분리
# ==============================
meta_cols = [c for c in ["file_path", "family", "label"] if c in df.columns]

if "label" not in df.columns:
    raise ValueError("label 컬럼이 없습니다.")

X = df.drop(columns=meta_cols, errors="ignore")
y = df["label"]

selected_features = X.columns.tolist()

print("\n===== FEATURE INFO =====")
print("num_features:", len(selected_features))
print("sample features:", selected_features[:10])

# ==============================
# 3. 최종 모델 생성
# ==============================
model = RandomForestClassifier(
    n_estimators=300, random_state=42, class_weight="balanced", n_jobs=-1
)

# ==============================
# 4. 전체 데이터 학습
# ==============================
model.fit(X, y)

print("\n===== TRAIN COMPLETE =====")
print("학습 완료")

# ==============================
# 5. 모델 저장
# ==============================
with open(model_path, "wb") as f:
    pickle.dump(model, f)

with open(feature_path, "wb") as f:
    pickle.dump(selected_features, f)

print("\n===== SAVE COMPLETE =====")
print("model saved to   :", model_path)
print("features saved to:", feature_path)
