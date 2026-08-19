#!/usr/bin/env python3
# ============================================================
# 모든 모델 Confusion Matrix 시각화
# ============================================================

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import warnings
warnings.filterwarnings('ignore')

from sklearn.svm import SVC
from sklearn.ensemble import (
    RandomForestClassifier, AdaBoostClassifier,
    GradientBoostingClassifier, VotingClassifier
)
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from xgboost import XGBClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, matthews_corrcoef, roc_auc_score
from imblearn.over_sampling import SMOTE
import itertools

# ============================================================
# 1. 데이터 로드 및 전처리
# ============================================================
df = pd.read_csv("malware_dataset.csv")
FEATURE_COLS = [c for c in df.columns if c not in ['PID', 'Label', 'Type']]
X = df[FEATURE_COLS].values
y = df['Label'].values

indices = np.arange(len(df))
X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
    X, y, indices, test_size=0.2, random_state=42, stratify=y)

scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s  = scaler.transform(X_test)

smote = SMOTE(random_state=42)
X_train_res, y_train_res = smote.fit_resample(X_train_s, y_train)

# ============================================================
# 2. 평가 함수
# ============================================================
def evaluate(model, X_tr, y_tr, X_te, y_te):
    model.fit(X_tr, y_tr)
    y_pred = model.predict(X_te)
    y_prob = model.predict_proba(X_te)[:, 1]
    cm = confusion_matrix(y_te, y_pred)
    tn, fp, fn, tp = cm.ravel()
    mcc  = matthews_corrcoef(y_te, y_pred)
    auc  = roc_auc_score(y_te, y_prob)
    rec  = tp/(tp+fn) if (tp+fn)>0 else 0
    prec = tp/(tp+fp) if (tp+fp)>0 else 0
    f1   = 2*prec*rec/(prec+rec) if (prec+rec)>0 else 0
    return {
        'cm': cm, 'TP':tp, 'TN':tn, 'FP':fp, 'FN':fn,
        'MCC':round(mcc,4), 'Recall':round(rec,4),
        'Precision':round(prec,4), 'F1':round(f1,4),
        'AUC':round(auc,4), 'model': model, 'y_pred': y_pred
    }

# ============================================================
# 3. 모델 학습
# ============================================================
standalone_models = {
    "SVM":                 SVC(kernel='rbf', C=1.0, gamma='scale',
                               probability=True, class_weight='balanced', random_state=42),
    "Random Forest":       RandomForestClassifier(n_estimators=100, class_weight='balanced',
                                                  random_state=42),
    "kNN":                 KNeighborsClassifier(n_neighbors=5),
    "Logistic\nRegression": LogisticRegression(max_iter=1000, class_weight='balanced',
                                               random_state=42),
    "MLP":                 MLPClassifier(hidden_layer_sizes=(100,50), max_iter=500,
                                         random_state=42),
    "AdaBoost":            AdaBoostClassifier(n_estimators=100, random_state=42),
    "Gradient\nBoosting":  GradientBoostingClassifier(n_estimators=100, random_state=42),
    "XGBoost":             XGBClassifier(n_estimators=100, eval_metric='logloss',
                                         random_state=42,
                                         scale_pos_weight=(y==0).sum()/(y==1).sum()),
}

print("[*] Standalone 모델 학습 중...")
standalone_results = {}
trained_models = {}
for name, model in standalone_models.items():
    res = evaluate(model, X_train_res, y_train_res, X_test_s, y_test)
    standalone_results[name] = res
    trained_models[name.replace('\n', ' ')] = res['model']
    print(f"  {name.replace(chr(10), ' ')}: MCC={res['MCC']} Recall={res['Recall']}")

# Ensemble
svm_m = trained_models["SVM"]
rf_m  = trained_models["Random Forest"]
knn_m = trained_models["kNN"]
lr_m  = trained_models["Logistic Regression"]
mlp_m = trained_models["MLP"]
ada_m = trained_models["AdaBoost"]
xgb_m = trained_models["XGBoost"]

ensemble_configs = {
    "SVM+RF\n+kNN":      {"estimators": [('svm',svm_m),('rf',rf_m),('knn',knn_m)], "weights": [1.2,0.99,0.78]},
    "SVM+RF\n+LR":       {"estimators": [('svm',svm_m),('rf',rf_m),('lr',lr_m)],   "weights": [1.2,0.99,0.75]},
    "SVM+RF\n+MLP":      {"estimators": [('svm',svm_m),('rf',rf_m),('mlp',mlp_m)], "weights": [1,1,1]},
    "SVM+RF\n+AdaBoost": {"estimators": [('svm',svm_m),('rf',rf_m),('ada',ada_m)], "weights": [1.2,0.99,0.78]},
    "SVM+RF\n+XGBoost":  {"estimators": [('svm',svm_m),('rf',rf_m),('xgb',xgb_m)], "weights": [1.2,0.99,0.7]},
}

print("[*] Ensemble 모델 학습 중...")
ensemble_results = {}
for name, cfg in ensemble_configs.items():
    voting = VotingClassifier(estimators=cfg["estimators"], voting='soft', weights=cfg["weights"])
    res = evaluate(voting, X_train_res, y_train_res, X_test_s, y_test)
    ensemble_results[name] = res
    print(f"  {name.replace(chr(10), ' ')}: MCC={res['MCC']} Recall={res['Recall']}")

# ============================================================
# 4. Confusion Matrix 시각화 함수
# ============================================================
def plot_cm(ax, cm, title, res):
    classes = ['Benign', 'Ransomware']
    im = ax.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)

    # 숫자 표시
    thresh = cm.max() / 2.0
    for i, j in itertools.product(range(cm.shape[0]), range(cm.shape[1])):
        ax.text(j, i, format(cm[i, j], 'd'),
                horizontalalignment="center",
                color="white" if cm[i, j] > thresh else "black",
                fontsize=14, fontweight='bold')

    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(classes, fontsize=8)
    ax.set_yticklabels(classes, fontsize=8)
    ax.set_xlabel('Predicted', fontsize=8)
    ax.set_ylabel('Actual', fontsize=8)

    # 제목에 주요 지표 포함
    ax.set_title(
        f"{title}\n"
        f"MCC={res['MCC']} | Recall={res['Recall']}\n"
        f"F1={res['F1']} | AUC={res['AUC']}",
        fontsize=7.5, pad=4
    )

    # TP/TN/FP/FN 라벨
    ax.text(-0.45, 0, 'TN', color='gray', fontsize=7, va='center')
    ax.text(1.45, 0, 'FP', color='red',  fontsize=7, va='center')
    ax.text(-0.45, 1, 'FN', color='red',  fontsize=7, va='center')
    ax.text(1.45, 1, 'TP', color='green', fontsize=7, va='center')

# ============================================================
# 5. Standalone Confusion Matrix (8개)
# ============================================================
print("[*] Standalone Confusion Matrix 저장 중...")
fig, axes = plt.subplots(2, 4, figsize=(20, 10))
fig.suptitle('Standalone Models - Confusion Matrix', fontsize=16, fontweight='bold', y=1.01)

for idx, (name, res) in enumerate(standalone_results.items()):
    row, col = idx // 4, idx % 4
    plot_cm(axes[row][col], res['cm'], name, res)

plt.tight_layout()
plt.savefig("confusion_standalone.png", dpi=150, bbox_inches='tight')
print("[*] confusion_standalone.png 저장 완료")

# ============================================================
# 6. Ensemble Confusion Matrix (5개)
# ============================================================
print("[*] Ensemble Confusion Matrix 저장 중...")
fig, axes = plt.subplots(1, 5, figsize=(25, 5))
fig.suptitle('Voting Ensemble Models - Confusion Matrix', fontsize=16, fontweight='bold')

for idx, (name, res) in enumerate(ensemble_results.items()):
    plot_cm(axes[idx], res['cm'], name, res)

plt.tight_layout()
plt.savefig("confusion_ensemble.png", dpi=150, bbox_inches='tight')
print("[*] confusion_ensemble.png 저장 완료")

# ============================================================
# 7. 전체 모델 한 장에 (13개)
# ============================================================
print("[*] 전체 Confusion Matrix 저장 중...")
all_results = {**standalone_results, **ensemble_results}
n = len(all_results)  # 13개

fig = plt.figure(figsize=(26, 10))
fig.suptitle('All Models - Confusion Matrix', fontsize=16, fontweight='bold')

for idx, (name, res) in enumerate(all_results.items()):
    ax = fig.add_subplot(2, 7, idx + 1)
    plot_cm(ax, res['cm'], name, res)

plt.tight_layout()
plt.savefig("confusion_all.png", dpi=150, bbox_inches='tight')
print("[*] confusion_all.png 저장 완료")

print("\n완료! 생성 파일:")
print("  - confusion_standalone.png  (Standalone 8개)")
print("  - confusion_ensemble.png    (Ensemble 5개)")
print("  - confusion_all.png         (전체 13개)")