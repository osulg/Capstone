#!/usr/bin/env python3
"""
최종 정적 모델 학습 + 배포 스크립트

- ~/static_test/result/byte_ngram/ 에서 n3_k1000 데이터셋 CSV를 찾아
  전체 데이터(501개)로 RandomForest를 학습하고,
- vocab JSON과 함께 ~/Capstone/models/static/ 에 배치한다.

실행:  python3 train_static_model.py
"""
import os
import sys
import glob
import json
import shutil

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier

STATIC_TEST = os.path.expanduser("~/static_test")
BYTE_DIR = os.path.join(STATIC_TEST, "result", "byte_ngram")
OUT_DIR = os.path.expanduser("~/Capstone/guardfs/models/static")

VOCAB_SRC = os.path.join(BYTE_DIR, "global_vocab_n3_k1000.json")
VOCAB_DST = os.path.join(OUT_DIR, "byte_ngram_vocab_n3_k1000.json")
MODEL_DST = os.path.join(OUT_DIR, "static_rf_n3_k1000.pkl")

NON_FEATURE = {"label", "family", "file_path", "file", "path", "sha256", "name"}


def find_dataset_csv() -> str:
    """n3_k1000 조합의 전체 데이터셋 CSV를 찾는다."""
    candidates = []
    for pattern in ("*n3*k1000*.csv", "*all*.csv", "*.csv"):
        candidates = [
            p for p in glob.glob(os.path.join(BYTE_DIR, pattern))
            if "n3" in os.path.basename(p) and "k1000" in os.path.basename(p)
        ]
        if candidates:
            break
    if not candidates:
        print(f"[!] {BYTE_DIR} 에서 n3_k1000 CSV를 못 찾음.")
        print("    아래 목록에서 데이터셋 CSV 이름을 확인해줘:")
        for p in sorted(glob.glob(os.path.join(BYTE_DIR, "*.csv"))):
            print("   ", p)
        sys.exit(1)
    # 가장 큰 파일 = 종합 데이터셋일 가능성이 높음
    candidates.sort(key=os.path.getsize, reverse=True)
    return candidates[0]


def load_vocab_as_list(path: str) -> list:
    """vocab JSON을 hex 문자열 리스트로 정규화한다."""
    with open(path, "r", encoding="utf-8") as f:
        v = json.load(f)
    if isinstance(v, list):
        return [str(x) for x in v]
    if isinstance(v, dict):
        # {"f_0": "hex", ...} 형태 → f_i 순서대로 "값"(hex 패턴)을 뽑는다
        print("[i] vocab이 dict 형태 → f_i 순서로 값(hex) 추출")
        return [str(v[f"f_{i}"]) for i in range(len(v))]
    print(f"[!] 알 수 없는 vocab 형식: {type(v)}")
    sys.exit(1)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    # 1) 데이터셋 로드
    csv_path = find_dataset_csv()
    print(f"[i] 데이터셋: {csv_path}")
    df = pd.read_csv(csv_path)
    print(f"[i] 행 {len(df)}, 컬럼 {len(df.columns)}")

    label_col = next(
        (c for c in df.columns if c.strip().lower() == "label"), None
    )
    if label_col is None:
        print("[!] label 컬럼이 없음. 컬럼 목록:", list(df.columns)[:20])
        sys.exit(1)

    feature_cols = [
        c for c in df.columns if c.strip().lower() not in NON_FEATURE
    ]
    X = df[feature_cols].apply(pd.to_numeric, errors="coerce").fillna(0)
    y = df[label_col].astype(int)

    print(f"[i] feature {len(feature_cols)}개 "
          f"(예: {feature_cols[:3]} ... {feature_cols[-2:]})")
    print(f"[i] 정상 {int((y == 0).sum())} / 악성 {int((y == 1).sum())}")

    if len(feature_cols) != 1000:
        print(f"[!] 경고: feature가 1000개가 아님 ({len(feature_cols)}개). "
              f"제외 대상 컬럼이 더 있는지 확인 필요.")

    # 2) 정규화 (실험 최종 조건: raw count → 행 합으로 나눈 비율)
    row_sums = X.sum(axis=1)
    already_normalized = bool((row_sums <= 1.5).all())
    if already_normalized:
        print("[i] CSV가 이미 정규화된 값으로 보임 → 그대로 사용")
    else:
        print("[i] raw count로 판단 → 행 합으로 정규화 적용")
        X = X.div(row_sums.replace(0, 1), axis=0)

    # 3) 전체 데이터로 최종 학습
    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X, y)
    print("[i] 학습 완료 (RandomForest, n_estimators=200)")

    # 4) 저장 + vocab 배포
    joblib.dump(model, MODEL_DST)
    vocab_list = load_vocab_as_list(VOCAB_SRC)
    if len(vocab_list) != len(feature_cols):
        print(f"[!] 경고: vocab {len(vocab_list)}개 != feature {len(feature_cols)}개")
    with open(VOCAB_DST, "w", encoding="utf-8") as f:
        json.dump(vocab_list, f)

    print(f"[✓] 모델  → {MODEL_DST}")
    print(f"[✓] vocab → {VOCAB_DST}")

    # 5) 즉석 sanity check: 정상/악성 각 1개 예측
    print("\n--- sanity check ---")
    sys.path.insert(0, os.path.expanduser("~/Capstone"))
    from guardfs.stage2.calculation.ml_risk import StaticAnalyzer

    analyzer = StaticAnalyzer()
    p_benign = analyzer.predict_proba_path("/bin/ls")
    print(f"/bin/ls (정상)     → 악성 확률 {p_benign}")

    mal = glob.glob(os.path.join(STATIC_TEST, "malware", "lockbit", "*")) \
        or glob.glob(os.path.join(STATIC_TEST, "malware", "*", "*"))
    mal = [m for m in mal if os.path.isfile(m)
           and "benign" not in m.lower()]
    if mal:
        p_mal = analyzer.predict_proba_path(mal[0])
        print(f"{os.path.basename(os.path.dirname(mal[0]))} 샘플 → 악성 확률 {p_mal}")
    else:
        print("(악성 샘플 폴더를 못 찾아 정상 파일만 확인)")


def common_prefix(cols):
    """f_0, f_1 ... 형태에서 접두어 추출 (byte_f_ 등 변형 대응)"""
    import re
    m = re.match(r"^(.*?)(\d+)$", cols[0])
    return m.group(1) if m else "f_"


if __name__ == "__main__":
    main()
