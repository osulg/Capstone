#!/usr/bin/env python3
# 가중치별 최적값 탐색

import pandas as pd
import numpy as np
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, matthews_corrcoef
from imblearn.over_sampling import SMOTE
import warnings
warnings.filterwarnings('ignore')

df = pd.read_csv("malware_dataset.csv")
FEATURE_COLS = [c for c in df.columns if c not in ['PID', 'Label', 'Type']]
X = df[FEATURE_COLS].values
y = df['Label'].values

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled  = scaler.transform(X_test)

smote = SMOTE(random_state=42)
X_train_res, y_train_res = smote.fit_resample(X_train_scaled, y_train)

print("weight | Recall | Precision |  F1   |  MCC  | TP | FN | FP")
print("-" * 65)

for w in [1, 2, 3, 4, 5, 6, 7, 8]:
    model = SVC(kernel='rbf', C=1.0, gamma='scale', probability=True,
                class_weight={0: 1, 1: w}, random_state=42)
    model.fit(X_train_res, y_train_res)
    y_pred = model.predict(X_test_scaled)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    mcc    = matthews_corrcoef(y_test, y_pred)
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    prec   = tp / (tp + fp) if (tp + fp) > 0 else 0
    f1     = 2 * prec * recall / (prec + recall) if (prec + recall) > 0 else 0
    print(f"  {w}    | {recall:.4f} | {prec:.4f}    | {f1:.4f} | {mcc:.4f} | {tp} | {fn} | {fp}")