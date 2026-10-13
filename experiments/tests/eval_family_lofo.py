#!/usr/bin/env python3
"""
패밀리별 LOFO 평가 (정적 + 동적 + fusion)

~/Capstone 에서 실행:
    source venv/bin/activate
    python3 experiments/tests/eval_family_lofo.py
"""
import json, glob, os
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

# ── 경로 설정 ─────────────────────────────────────────────────────
CAPSTONE     = os.path.expanduser("~/Capstone")
DYN_MODEL    = f"{CAPSTONE}/models/dynamic/dataset/csv_files/best_model.pkl"
DYN_SCALER   = f"{CAPSTONE}/models/dynamic/dataset/csv_files/scaler.pkl"
STAT_MODEL   = f"{CAPSTONE}/models/static/static_rf_n3_k1000.pkl"
STAT_VOCAB   = f"{CAPSTONE}/models/static/byte_ngram_vocab_n3_k1000.json"
DYN_CSV      = f"{CAPSTONE}/models/dynamic/dataset/csv_files/malware_dataset.csv"
STATIC_BASE  = os.path.expanduser("~/static_test/result/byte_ngram")

# ── 하이퍼파라미터 ────────────────────────────────────────────────
HIGH_TH  = 0.82   # HIGH 임계
MED_TH   = 0.30   # MEDIUM / SUSPICIOUS 임계 (탐지 기준)
DYN_W    = 0.5
STAT_W   = 0.5

# ── 세션 해시 → 패밀리 매핑 ──────────────────────────────────────
TYPE_TO_FAMILY = {
    "0cd7b": "AvosLocker", "7c935": "AvosLocker", "10ab7": "AvosLocker",
    "d7112": "AvosLocker", "e9a7b": "AvosLocker",
    "3a08e": "blackcat",   "5121f": "blackcat",   "f8c08": "blackcat",
    "53bf4": "Babuk",      "113c3": "Babuk",       "6891c": "Babuk",
    "87db7": "Babuk",      "a1145": "Babuk",       "bed50": "Babuk",
    "dc905": "Babuk",
    "8f3db": "HelloKitty", "16a00": "HelloKitty", "556e5": "HelloKitty",
    "754f2": "HelloKitty", "b4f90": "HelloKitty", "ca607": "HelloKitty",
    "e9cc7": "IceFire",
    "edfe8": "MONTI",
    "4dc06": "lockbit",
    "3d375": "REvil",      "79680": "REvil",       "d6762": "REvil",
    "ea187": "REvil",      "f8649": "REvil",
    "6a882": "wiper",
}

FEATURE_COLS = [
    "O_sum","C_sum","D_sum","E_sum","Is_System_Path","Is_Test_Path","is_dev",
    "CCC","CCD","CCO","CDC","CDD","CDO","COC","COD","COO",
    "DCC","DCD","DCO","DDC","DDD","DDO","DOC","DOD","DOO",
    "EEE","EEO","EOE","EOO","OCC","OCD","OCO","ODC","ODD","ODO","OEE",
    "OOC","OOD","OOO"
]

def main():
    # ── 모델 로드 ──────────────────────────────────────────────────
    print("[1/3] 모델 로드...")
    dyn_model  = joblib.load(DYN_MODEL)
    dyn_scaler = joblib.load(DYN_SCALER)
    stat_model = joblib.load(STAT_MODEL)
    vocab      = json.load(open(STAT_VOCAB))
    stat_cols  = [f"f_{i}" for i in range(len(vocab))]
    print(f"    동적 모델: {DYN_MODEL.split('/')[-1]}")
    print(f"    정적 모델: k={len(vocab)}")

    # ── 동적 CSV 로드 + 패밀리 매핑 ───────────────────────────────
    print("[2/3] 데이터 로드...")
    df = pd.read_csv(DYN_CSV)
    df["Family"] = df["Type"].map(TYPE_TO_FAMILY)
    mal_df = df[df["Label"]==1].copy()
    ben_df = df[df["Label"]==0].copy()
    print(f"    악성 {len(mal_df)}행 / 정상 {len(ben_df)}행")
    print(f"    패밀리 매핑 성공: {mal_df['Family'].notna().sum()}/{len(mal_df)}")

    # ── 정적 CSV 로드 (패밀리별) ───────────────────────────────────
    static_data = {}
    for fam in mal_df["Family"].dropna().unique():
        csvs = glob.glob(f"{STATIC_BASE}/{fam}/*_n3_k1000_dataset.csv")
        if not csvs:
            continue
        sdf = pd.read_csv(csvs[0])
        lc  = next((c for c in sdf.columns if c.lower() == "label"), None)
        fc  = [c for c in stat_cols if c in sdf.columns]
        if lc and len(fc) > 100:
            static_data[fam] = (sdf, lc, fc)
    print(f"    정적 CSV 로드: {len(static_data)}개 패밀리")

    # ── 패밀리별 LOFO ─────────────────────────────────────────────
    print("\n[3/3] 패밀리별 LOFO 평가...\n")
    families = sorted(mal_df["Family"].dropna().unique())

    header = f"{'패밀리':<14} {'n':>3}  {'dyn':>6}  {'stat':>6}  {'fusion':>7}  상태"
    print(header)
    print("─" * 60)

    rows = []
    X_ben = ben_df[FEATURE_COLS].fillna(0)
    y_ben = ben_df["Label"]

    for fam in families:
        fam_mask = mal_df["Family"] == fam
        X_test = mal_df.loc[fam_mask, FEATURE_COLS].fillna(0)
        n = len(X_test)

        # 해당 패밀리 제외하고 학습 (LOFO)
        X_tr_mal = mal_df.loc[~fam_mask, FEATURE_COLS].fillna(0)
        y_tr_mal = mal_df.loc[~fam_mask, "Label"]
        X_tr = pd.concat([X_tr_mal, X_ben])
        y_tr = pd.concat([y_tr_mal, y_ben])

        X_tr_sc = dyn_scaler.transform(X_tr)
        X_te_sc = dyn_scaler.transform(X_test)
        dyn_model.fit(X_tr_sc, y_tr)
        dyn_prob = dyn_model.predict_proba(X_te_sc)[:, 1]
        dyn_recall = float((dyn_prob >= MED_TH).mean())

        # 정적 recall
        stat_recall = None
        if fam in static_data:
            sdf, lc, fc = static_data[fam]
            smal = sdf[sdf[lc] == 1]
            if len(smal):
                sp = stat_model.predict_proba(smal[fc])[:, 1]
                stat_recall = float((sp >= 0.5).mean())

        # fusion recall (dyn 단독 OR fusion 점수)
        fusion_recall = None
        if stat_recall is not None:
            # 샘플 수 맞추기: 정적은 파일 단위, 동적은 PID 단위라
            # 여기선 보수적으로 둘 중 낮은 쪽을 fusion에 반영
            # (실제론 같은 실행 세션 기준으로 평균내야 하지만
            #  현재 데이터 구조상 불가 → 독립 평가 후 OR 조건)
            fusion_recall = max(dyn_recall,
                                (dyn_recall * DYN_W + stat_recall * STAT_W))
            # dyn 단독 HIGH 조건 추가 시
            dyn_high_recall = float((dyn_prob >= HIGH_TH).mean())
            fusion_or_recall = float(
                ((dyn_prob >= HIGH_TH) |
                 ((DYN_W * dyn_prob + STAT_W * stat_recall) >= HIGH_TH)).mean()
            )

        # 상태 태그
        dr = dyn_recall
        sr = stat_recall if stat_recall is not None else 0
        best = max(dr, sr if stat_recall else 0)
        if best >= 0.9:   status = "✅ 양호"
        elif best >= 0.5: status = "⚠️  주의"
        else:             status = "❌ 취약"

        stat_str   = f"{stat_recall:.3f}" if stat_recall is not None else "  N/A"
        fusion_str = f"{fusion_recall:.3f}" if fusion_recall is not None else "  N/A"

        print(f"{fam:<14} {n:>3}  {dr:>6.3f}  {stat_str:>6}  {fusion_str:>7}  {status}")
        rows.append({
            "family": fam, "n": n,
            "dyn_recall": dr,
            "stat_recall": stat_recall,
            "fusion_recall": fusion_recall,
        })

    # ── 요약 ──────────────────────────────────────────────────────
    print("\n" + "═" * 60)
    print("▶ 요약")
    weak = [r for r in rows if (r["dyn_recall"] < 0.5 and
                                 (r["stat_recall"] is None or r["stat_recall"] < 0.5))]
    dyn_only_weak = [r for r in rows if r["dyn_recall"] < 0.5]
    stat_strong   = [r for r in rows if r["stat_recall"] is not None
                     and r["stat_recall"] >= 0.9]

    print(f"  정적 단독으로 잘 잡히는 패밀리 (recall≥0.9): "
          f"{[r['family'] for r in stat_strong]}")
    print(f"  동적 취약 (recall<0.5): "
          f"{[r['family'] for r in dyn_only_weak]}")
    print(f"  정적+동적 모두 취약: "
          f"{[r['family'] for r in weak] or '없음'}")
    print()
    print("▶ 수집 우선순위 (동적 recall 낮은 순)")
    sorted_rows = sorted(rows, key=lambda r: r["dyn_recall"])
    for r in sorted_rows:
        if r["dyn_recall"] < 0.8:
            comp = ""
            if r["stat_recall"] is not None and r["stat_recall"] >= 0.9:
                comp = " → 정적이 보완 중"
            elif r["stat_recall"] is not None and r["stat_recall"] < 0.5:
                comp = " → 둘 다 취약! 최우선"
            print(f"  {r['family']:<14} dyn={r['dyn_recall']:.3f}"
                  f"  stat={str(round(r['stat_recall'],3)) if r['stat_recall'] else 'N/A'}{comp}")


if __name__ == "__main__":
    main()
