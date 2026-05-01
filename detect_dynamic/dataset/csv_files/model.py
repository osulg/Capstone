#!/usr/bin/env python3
# ============================================================
# 랜섬웨어 탐지 ML 모델 전체 실험
# 참고: Ransomware Detection in Linux Systems Using eBPF and AI
# Standalone 8개 + Voting Ensemble 5개 = 총 13개 모델
# ============================================================

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
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
from sklearn.metrics import (
    confusion_matrix, matthews_corrcoef,
    roc_auc_score, roc_curve
)
from imblearn.over_sampling import SMOTE
import joblib

# ============================================================
# 1. 데이터 로드
# ============================================================
print("=" * 65)
print(" 랜섬웨어 탐지 전체 모델 실험 (Standalone + Voting Ensemble)")
print("=" * 65)

df = pd.read_csv("malware_dataset.csv")
FEATURE_COLS = [c for c in df.columns if c not in ['PID', 'Label', 'Type']]
X = df[FEATURE_COLS].values
y = df['Label'].values
print(f"\n[*] 데이터: {df.shape[0]}행 / 정상: {(y==0).sum()} / 악성: {(y==1).sum()}")

# ============================================================
# 2. Train/Test 분리 (8:2) - 원본 인덱스 함께 보존
# ============================================================
indices = np.arange(len(df))
X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
    X, y, indices, test_size=0.2, random_state=42, stratify=y)
print(f"[*] Train: {len(X_train)} / Test: {len(X_test)} (8:2 split)")

# ============================================================
# 3. 스케일링 + SMOTE
# ============================================================
scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s  = scaler.transform(X_test)

smote = SMOTE(random_state=42)
X_train_res, y_train_res = smote.fit_resample(X_train_s, y_train)
print(f"[*] SMOTE 후 Train: {len(X_train_res)} (악성: {y_train_res.sum()})")

# ============================================================
# 4. 평가 함수 (FN 분석 포함)
# ============================================================
def evaluate(model, X_tr, y_tr, X_te, y_te):
    model.fit(X_tr, y_tr)
    y_pred = model.predict(X_te)
    y_prob = model.predict_proba(X_te)[:, 1]
    tn, fp, fn, tp = confusion_matrix(y_te, y_pred).ravel()
    mcc  = matthews_corrcoef(y_te, y_pred)
    auc  = roc_auc_score(y_te, y_prob)
    rec  = tp/(tp+fn) if (tp+fn)>0 else 0
    prec = tp/(tp+fp) if (tp+fp)>0 else 0
    f1   = 2*prec*rec/(prec+rec) if (prec+rec)>0 else 0
    acc  = (tp+tn)/(tp+tn+fp+fn)
    spec = tn/(tn+fp) if (tn+fp)>0 else 0
    return {
        'TP':tp,'TN':tn,'FP':fp,'FN':fn,
        'MCC':round(mcc,4), 'Precision':round(prec,4),
        'Recall':round(rec,4), 'Specificity':round(spec,4),
        'F1':round(f1,4), 'Accuracy':round(acc,4),
        'AUC':round(auc,4), 'model':model,
        'y_prob':y_prob, 'y_pred':y_pred
    }

def print_fn_samples(name, res, y_te, idx_te):
    """FN 샘플 (놓친 랜섬웨어) 출력"""
    y_pred = res['y_pred']
    fn_indices = np.where((y_te == 1) & (y_pred == 0))[0]
    print(f"\n  [놓친 랜섬웨어 FN={len(fn_indices)}개]")
    if len(fn_indices) == 0:
        print("  → 없음! 완벽 탐지")
        return
    for i in fn_indices:
        orig_idx = idx_te[i]
        row = df.iloc[orig_idx]
        print(f"  → PID={int(row['PID'])} | Type={row['Type']} | "
              f"O_sum={int(row['O_sum'])} | C_sum={int(row['C_sum'])} | "
              f"D_sum={int(row['D_sum'])}")

def print_fp_samples(name, res, y_te, idx_te):
    """FP 샘플 (오탐된 정상) 출력"""
    y_pred = res['y_pred']
    fp_indices = np.where((y_te == 0) & (y_pred == 1))[0]
    print(f"  [오탐 정상 FP={len(fp_indices)}개]")
    if len(fp_indices) == 0:
        print("  → 없음!")
        return
    for i in fp_indices:
        orig_idx = idx_te[i]
        row = df.iloc[orig_idx]
        print(f"  → PID={int(row['PID'])} | Type={row['Type']} | "
              f"O_sum={int(row['O_sum'])} | C_sum={int(row['C_sum'])} | "
              f"D_sum={int(row['D_sum'])}")

# ============================================================
# 5. Standalone 모델
# ============================================================
standalone_models = {
    "SVM":                 SVC(kernel='rbf', C=1.0, gamma='scale',
                               probability=True, class_weight='balanced', random_state=42),
    "Random Forest":       RandomForestClassifier(n_estimators=100, class_weight='balanced',
                                                  random_state=42),
    "kNN":                 KNeighborsClassifier(n_neighbors=5),
    "Logistic Regression": LogisticRegression(max_iter=1000, class_weight='balanced',
                                               random_state=42),
    "MLP":                 MLPClassifier(hidden_layer_sizes=(100,50), max_iter=500,
                                         random_state=42),
    "AdaBoost":            AdaBoostClassifier(n_estimators=100, random_state=42),
    "Gradient Boosting":   GradientBoostingClassifier(n_estimators=100, random_state=42),
    "XGBoost":             XGBClassifier(n_estimators=100, eval_metric='logloss',
                                         random_state=42,
                                         scale_pos_weight=(y==0).sum()/(y==1).sum()),
}

print("\n" + "=" * 65)
print(" [Standalone 모델 결과]")
print("=" * 65)

standalone_results = {}
trained_models = {}

for name, model in standalone_models.items():
    res = evaluate(model, X_train_res, y_train_res, X_test_s, y_test)
    standalone_results[name] = res
    trained_models[name] = res['model']
    print(f"\n[{name}]")
    print(f"  TP={res['TP']} TN={res['TN']} FP={res['FP']} FN={res['FN']}")
    print(f"  MCC={res['MCC']} | Recall={res['Recall']} | Precision={res['Precision']}")
    print(f"  F1={res['F1']} | AUC={res['AUC']} | Accuracy={res['Accuracy']} | Specificity={res['Specificity']}")
    print_fn_samples(name, res, y_test, idx_test)
    print_fp_samples(name, res, y_test, idx_test)

# 표 저장
metrics = ['MCC','Precision','Recall','Specificity','F1','Accuracy','AUC']
standalone_df = pd.DataFrame(
    {n: {m: standalone_results[n][m] for m in metrics} for n in standalone_results}
).T
standalone_df.to_csv("standalone_results.csv")
print("\n[Standalone 성능 비교표]")
print(standalone_df.to_string())

# ============================================================
# 6. Voting Ensemble (논문 Table VII 가중치)
# ============================================================
svm_m = trained_models["SVM"]
rf_m  = trained_models["Random Forest"]
knn_m = trained_models["kNN"]
lr_m  = trained_models["Logistic Regression"]
mlp_m = trained_models["MLP"]
ada_m = trained_models["AdaBoost"]
xgb_m = trained_models["XGBoost"]

ensemble_configs = {
    "SVM+RF+kNN":      {"estimators": [('svm',svm_m),('rf',rf_m),('knn',knn_m)], "weights": [1.2,0.99,0.78]},
    "SVM+RF+LR":       {"estimators": [('svm',svm_m),('rf',rf_m),('lr',lr_m)],   "weights": [1.2,0.99,0.75]},
    "SVM+RF+MLP":      {"estimators": [('svm',svm_m),('rf',rf_m),('mlp',mlp_m)], "weights": [1,1,1]},
    "SVM+RF+AdaBoost": {"estimators": [('svm',svm_m),('rf',rf_m),('ada',ada_m)], "weights": [1.2,0.99,0.78]},
    "SVM+RF+XGBoost":  {"estimators": [('svm',svm_m),('rf',rf_m),('xgb',xgb_m)], "weights": [1.2,0.99,0.7]},
}

print("\n" + "=" * 65)
print(" [Voting Ensemble 결과]")
print("=" * 65)

ensemble_results = {}

for name, cfg in ensemble_configs.items():
    voting = VotingClassifier(estimators=cfg["estimators"], voting='soft', weights=cfg["weights"])
    res = evaluate(voting, X_train_res, y_train_res, X_test_s, y_test)
    ensemble_results[name] = res
    print(f"\n[{name}]")
    print(f"  TP={res['TP']} TN={res['TN']} FP={res['FP']} FN={res['FN']}")
    print(f"  MCC={res['MCC']} | Recall={res['Recall']} | Precision={res['Precision']}")
    print(f"  F1={res['F1']} | AUC={res['AUC']} | Accuracy={res['Accuracy']} | Specificity={res['Specificity']}")
    print_fn_samples(name, res, y_test, idx_test)
    print_fp_samples(name, res, y_test, idx_test)

ensemble_df = pd.DataFrame(
    {n: {m: ensemble_results[n][m] for m in metrics} for n in ensemble_results}
).T
ensemble_df.to_csv("ensemble_results.csv")
print("\n[Ensemble 성능 비교표]")
print(ensemble_df.to_string())

# ============================================================
# 7. 시각화
# ============================================================
all_results = {**standalone_results, **ensemble_results}
names   = list(all_results.keys())
mccs    = [all_results[n]['MCC']    for n in names]
recalls = [all_results[n]['Recall'] for n in names]
colors  = ['steelblue']*len(standalone_models) + ['tomato']*len(ensemble_configs)

fig, axes = plt.subplots(1, 2, figsize=(18, 7))
axes[0].barh(names, mccs, color=colors)
axes[0].axvline(x=0.6940, color='green', linestyle='--', label='기준(SVM) MCC=0.694')
axes[0].set_xlabel("MCC"); axes[0].set_title("MCC 비교\n(파랑=Standalone / 빨강=Ensemble)")
axes[0].legend()
axes[1].barh(names, recalls, color=colors)
axes[1].axvline(x=1.0, color='red', linestyle='--', label='목표 Recall=1.0')
axes[1].set_xlabel("Recall"); axes[1].set_title("Recall 비교")
axes[1].legend()
plt.tight_layout()
plt.savefig("model_comparison.png", dpi=150, bbox_inches='tight')
print("\n[*] model_comparison.png 저장 완료")

# ROC Curve
plt.figure(figsize=(10, 7))
for name, res in all_results.items():
    fpr, tpr, _ = roc_curve(y_test, res['y_prob'])
    style = '-' if name in standalone_results else '--'
    plt.plot(fpr, tpr, linestyle=style, label=f"{name} (AUC={res['AUC']})")
plt.plot([0,1],[0,1],'k:', label='Random')
plt.xlabel("FPR"); plt.ylabel("TPR"); plt.title("ROC Curve")
plt.legend(bbox_to_anchor=(1.05,1), loc='upper left', fontsize=8)
plt.tight_layout()
plt.savefig("roc_curve_all.png", dpi=150, bbox_inches='tight')
print("[*] roc_curve_all.png 저장 완료")

# ============================================================
# 8. 최적 모델 저장
# ============================================================
best_name = max(all_results, key=lambda x: all_results[x]['MCC'])
print(f"\n[*] 최적 모델: {best_name} (MCC={all_results[best_name]['MCC']})")
joblib.dump(all_results[best_name]['model'], "best_model.pkl")
joblib.dump(scaler, "scaler.pkl")
print("[*] best_model.pkl / scaler.pkl 저장 완료")

print("\n완료! 생성 파일: standalone_results.csv / ensemble_results.csv / model_comparison.png / roc_curve_all.png")