# 동적 모델 v5 — 성능 결과 (FUSE-only · PID 단위)

런타임(GuardFS 탐지)이 실제로 보는 신호에 맞춘 동적 모델. `*.fuse.jsonl`
로그를 **PID 단위**로 재집계해 학습했다(재수집 없음). 런타임 `PidStats`가
내는 피처와 **바이트 단위로 동일**함을 검증했다(학습=추론).

## 데이터셋

- **3420 PID 샘플** = 정상 3382 + 악성 38
  - 정상에는 악성 run의 prep/수집 하네스 PID도 포함(lineage 라벨링으로 분리)
- 악성 **11개 패밀리**: avoslocker(5), babuk(7), braincipher(2), buhti(1),
  conti(4), hellokitty(6), incransom(4), moneymessage(1), monti(1),
  ransomexx(2), revil(5)
- 피처 **22개**: features.py의 24개 중 `proc_count`(PID단위라 상수 1),
  `crypto_calls`(FUSE엔 CRYPTO op 없음) 제외
- 라벨: eBPF lineage 기반 악성 서브트리만 1, prep/하네스는 0 (수동 지정 없음)

## 최종 성능

### 1) 지도학습 RandomForest (5-fold 교차검증 OOF)

| 지표 | 값 |
|------|----|
| 탐지율(Recall) | **97.4%** (38개 중 37개) |
| 오탐률(FPR) | **0%** (정상 3382개 전부 정상 판정) |
| 정상 OOF 점수 최대 | 0.145 |
| 악성 OOF 점수(미탐 제외) | 대부분 0.9+ |

정상 최대 0.145 vs 악성 0.9+ → **임계값 0.3~0.80 어디서든 FPR 0% / 97.4%**.
유일한 미탐은 moneymessage 1개(부분감염 run, 점수 0.048) — v4에서도 못 잡던 것.

### 2) 워크로드 그룹 교차검증 (같은 워크로드가 train/val에 안 섞임)

| 지표 | 값 |
|------|----|
| 탐지율 | **97.4%** |
| 오탐률 | **0.2%** (3382개 중 8개) |

### 3) Leave-One-Family-Out (처음 보는 악성 패밀리)

한 패밀리를 학습에서 완전히 제외하고 그 패밀리를 탐지:

| 패밀리 | 탐지 |
|--------|------|
| avoslocker, babuk, braincipher, buhti, conti, hellokitty, incransom, monti, ransomexx, revil | **100%** |
| moneymessage | 0% (1개, 부분감염) |
| **평균 (안 본 패밀리)** | **97.4%** (37/38) |

→ **run 단위 v4(LOFO 89.5%)보다 오히려 높다.** PID 단위 + 전 패밀리 lineage
라벨링으로 "랜섬웨어 공통 행동"이 더 또렷해졌다.

## 동적 단독 HIGH 임계값

`STAGE2_DYN_ONLY_HIGH_THRESHOLD = 0.5` (config.py). 정적 점수와 무관하게
동적이 0.5 이상이면 HIGH로 격상 → 실행 파일이 양성 인터프리터(python3)인
스크립트형 랜섬웨어도 차단 가능. FPR 0% 되는 최저값은 0.3이며, 0.5는 정상
최대(0.145) 대비 큰 여유를 두면서 탐지율(97.4%) 손실이 없는 값.

## 가장 중요한 판별 피처

v4와 동일 계열: `read_then_overwrite_ratio`, `ext_change_rename_ratio`,
`high_entropy_write_count/ratio`, `mean_write_bytes`, `distinct_ext_after_rename`.
모두 FUSE-only로 산출 가능 → 런타임에서 그대로 재현된다.

## 재현

```bash
# 1) 피처 추출 (원시 로그 → PID 단위 CSV)  ※ 이미 features_perpid.csv 로 커밋됨
python3 models/dynamic/collect/extract_perpid_fuse.py \
    --collect-dir <fuse/ebpf 로그 폴더> \
    --labels models/dynamic/dataset_v4/labels.csv \
    --ebpf-dir <같은 폴더> \
    --out models/dynamic/dataset_v5/features_perpid.csv

# 2) 학습 + 성능 + 모델 저장  ※ 반드시 GuardFS venv(배포 sklearn)에서
python3 models/dynamic/collect/train_v5.py \
    --features models/dynamic/dataset_v5/features_perpid.csv \
    --out-model models/dynamic/rf_model_v5.pkl \
    --out-cols  models/dynamic/feature_cols_v5.json
```
