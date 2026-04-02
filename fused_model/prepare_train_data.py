import pandas as pd
import os
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_selection import SelectKBest, chi2

# ===============================
# 경로 설정
# ===============================
input_csv = "/home/osulg/capstone/Result/preprocessed_features.csv"
save_dir = "/home/osulg/capstone/Result/train_data"

os.makedirs(save_dir, exist_ok=True)

# ===============================
# CSV 로드
# ===============================
df = pd.read_csv(input_csv)

print("\n===== LOAD DATA =====")
print("shape:", df.shape)

# ===============================
# X / y 분리
# ===============================
X = df.drop(columns=["label"])
y = df["label"]

print("\n===== X / y INFO =====")
print("X shape:", X.shape)
print("y shape:", y.shape)
print("\n[label distribution]")
print(y.value_counts())

# ===============================
# train / test split
# ===============================
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("\n===== TRAIN / TEST SPLIT =====")
print("X_train shape:", X_train.shape)
print("X_test shape :", X_test.shape)
print("y_train shape:", y_train.shape)
print("y_test shape :", y_test.shape)

# ===============================
# feature selection
# 반드시 train에만 fit
# ===============================
k = 200

selector = SelectKBest(score_func=chi2, k=k)
X_train_selected = selector.fit_transform(X_train, y_train)
X_test_selected = selector.transform(X_test)

print("\n===== FEATURE SELECTION =====")
print("k:", k)
print("X_train_selected shape:", X_train_selected.shape)
print("X_test_selected shape :", X_test_selected.shape)

# 선택된 feature 이름 확인
selected_features = X.columns[selector.get_support()].tolist()
selected_features_df = pd.DataFrame({"selected_feature": selected_features})
selected_features_df.to_csv(
    os.path.join(save_dir, "selected_features_k200.csv"),
    index=False
)

# ===============================
# 저장
# ===============================
joblib.dump(selector, os.path.join(save_dir, "selector_k200.pkl"))

pd.DataFrame(X_train_selected).to_csv(
    os.path.join(save_dir, "X_train_k200.csv"), index=False
)
pd.DataFrame(X_test_selected).to_csv(
    os.path.join(save_dir, "X_test_k200.csv"), index=False
)
pd.DataFrame(y_train, columns=["label"]).to_csv(
    os.path.join(save_dir, "y_train.csv"), index=False
)
pd.DataFrame(y_test, columns=["label"]).to_csv(
    os.path.join(save_dir, "y_test.csv"), index=False
)

print("\n저장 완료:")
print(os.path.join(save_dir, "X_train_k200.csv"))
print(os.path.join(save_dir, "X_test_k200.csv"))
print(os.path.join(save_dir, "y_train.csv"))
print(os.path.join(save_dir, "y_test.csv"))
print(os.path.join(save_dir, "selector_k200.pkl"))
print(os.path.join(save_dir, "selected_features_k200.csv"))