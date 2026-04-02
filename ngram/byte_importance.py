import pandas as pd
from sklearn.ensemble import RandomForestClassifier

csv_files = {
    "byte_n3_k300": "/home/osulg/capstone/Result/byte_ngram/byte_ngram_n3_k300_all_dataset.csv",
    "opcode_n3_k500": "/home/osulg/capstone/Result/opcode_ngram/opcode_ngram_n3_k500_all_dataset.csv",
}

for exp_name, csv_path in csv_files.items():
    print(f"\n===== {exp_name} =====")

    df = pd.read_csv(csv_path)

    drop_cols = [col for col in ["file_path", "family", "label"] if col in df.columns]
    X = df.drop(columns=drop_cols)
    y = df["label"]

    model = RandomForestClassifier(
        n_estimators=200, random_state=42, class_weight="balanced"
    )
    model.fit(X, y)

    importance_df = pd.DataFrame(
        {"feature": X.columns, "importance": model.feature_importances_}
    ).sort_values(by="importance", ascending=False)

    print(importance_df.head(20).to_string(index=False))
