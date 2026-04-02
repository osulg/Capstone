import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

"""
- byte_ngram에서 1차로 실행한 성능 비교 코드
- train/test로 데이터를 분리하여 진행
- 따라서, 모든 데이터가 train과 test에 모두 속함에 따라 값이 1.0으로 나옴 확임
- 또한, 데이터가 너무 적어 값이 제대로 나올 가능성이 적음
=> (결론) 3 
"""


# ===============================
# CSV 경로
# ===============================

csv_files = {
    "n2_k300": "/home/osulg/capstone/Result/byte_ngram/byte_ngram_n2_k300_all_dataset.csv",
    "n2_k500": "/home/osulg/capstone/Result/byte_ngram/byte_ngram_n2_k500_all_dataset.csv",
    "n2_k1000": "/home/osulg/capstone/Result/byte_ngram/byte_ngram_n2_k1000_all_dataset.csv",
    "n3_k300": "/home/osulg/capstone/Result/byte_ngram/byte_ngram_n3_k300_all_dataset.csv",
    "n3_k500": "/home/osulg/capstone/Result/byte_ngram/byte_ngram_n3_k500_all_dataset.csv",
    "n3_k1000": "/home/osulg/capstone/Result/byte_ngram/byte_ngram_n3_k1000_all_dataset.csv",
}

results = []

for name, path in csv_files.items():

    print(f"\n===== {name} =====")

    df = pd.read_csv(path)

    y = df["label"]
    X = df.drop(columns=["family", "label", "file_path"], errors="ignore")

    # split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    # model
    model = RandomForestClassifier(n_estimators=200, random_state=42)

    model.fit(X_train, y_train)

    pred = model.predict(X_test)

    acc = accuracy_score(y_test, pred)
    prec = precision_score(y_test, pred)
    rec = recall_score(y_test, pred)
    f1 = f1_score(y_test, pred)

    print("accuracy :", acc)
    print("precision:", prec)
    print("recall   :", rec)
    print("f1-score :", f1)

    results.append([name, acc, prec, rec, f1])


# 결과 정리
result_df = pd.DataFrame(
    results, columns=["experiment", "accuracy", "precision", "recall", "f1"]
)

print("\n===== RESULT TABLE =====")
print(result_df)
