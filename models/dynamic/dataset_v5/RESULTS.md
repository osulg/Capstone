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

## 런타임 검증 (VM, GuardFS detection 모드 실제 실행)

오프라인 교차검증과 별개로, 실제 GuardFS에서 Stage1 -> Stage2 전체 경로를 돌려 확인했다.
정적 점수는 python3 인터프리터 기준 0.295(양성)라, 동적 단독 HIGH 규칙
(`STAGE2_DYN_ONLY_HIGH_THRESHOLD = 0.5`)이 없으면 스크립트형 공격은 가중합 상한
0.65에 막혀 HIGH가 될 수 없다.

### 공격 시뮬레이터 (`experiments/simulators/sim_highentropy.py`)

실제 랜섬웨어가 아닌 부하 생성기(읽고 난수로 덮어쓰기 + 확장자 변경 rename).

| 시각 | 동적 점수 | 판정 |
|------|----------|------|
| Stage1 첫 트리거 직후 | 0.107 | 관찰 창 시작 (이벤트가 적어 낮음) |
| 관찰 0.9초 | 0.730 | `[TRIGGER HIGH] reason=watch_dyn_only=0.730`, 시뮬레이터 SIGSTOP |

- 관찰 창 도입(`1800507`) 직후 실행에서는 2.0초에 HIGH(dyn 0.713)였고, 재평가 타이머
  수정(`3b2d63c`) 이후 같은 시나리오를 다시 돌려 0.9초에 HIGH로 격상됨을 확인했다.
- 각 1회 실행 결과이며, 시뮬레이터 규모를 학습 분포(파일 20개, 총 1.3MB)에 맞춘 값이다.

### 정상 작업 오탐 점검

| 테스트 | 관찰 PID | HIGH | MEDIUM | 동적 점수 최대 |
|--------|---------|------|--------|--------------|
| `head`/`tar`/`cp`/`mv` 셸 루프 (짧은 프로세스 다수) | 약 45 | 0 | 0 | 0.142 |
| `shred -n 1 -u`, `rsync -a`, 한 프로세스 확장자 일괄 변경, `gzip -r` | (필터 상 0.3 이상 1개) | 0 | 0 | 0.395 |

- 두 번째 테스트의 0.395는 PID 1개이며 어느 명령인지는 로그로 특정하지 못했다.
  HIGH 기준 0.5와의 간격은 0.105다.
- 오프라인 워크로드 단위 교차검증(학습에서 그 워크로드를 제외)에서도 정상 3382 PID 중
  동적 점수 0.5 이상은 0개였고, 가장 높은 워크로드는 `shred_delete`(0.455), 다음은
  `rsync_mirror`(0.25), `git_checkout`(0.175)였다. shred는 HIGH 기준과 간격이 0.045로
  가장 좁다.

### 이번에 발견·수정한 Stage2 구조 문제

1. 첫 점수가 MEDIUM(0.3) 미만이면 곧바로 LOW로 내려 10초 재평가 창이 열리지 않았고,
   PID가 `_queued_stage2`에 남아 SUSPICIOUS에 영구히 갇혔다(SUSPICIOUS 쓰기는 통과).
   -> 첫 점수가 낮아도 `STAGE2_WATCH_TIMEOUT_SEC`(10초) 관찰 창을 열고 1초마다 재채점.
2. 재평가 타이머(`next_reeval`)가 이벤트를 처리할 때마다 1초씩 밀려, 의심 PID가 많으면
   관찰 창이 20초 이상으로 늘었다(가짜 ops 하네스 재현: 20.1~21.0초 -> 수정 후 10.0~11.0초,
   실제 GuardFS 로그에서도 재평가 간격 약 1초 확인).

## 한계 (알려진 것)

- **규모 의존**: 중요도 상위에 `total_write_bytes`, `unique_files_touched`,
  `files_per_dir`, `high_entropy_write_count`가 포함돼 있고, 학습에 쓴 악성 run은
  수집 환경상 파일 약 20개/총 1.3MB를 암호화한 것이다. 합성 패턴 측정에서 같은 행동을
  수십 pass 반복하거나 파일을 수백 개로 늘리면 동적 점수가 0.31~0.46으로 낮아졌다
  (20파일 1 pass는 0.69). 대량 암호화 랜섬웨어에서는 점수가 낮아질 위험이 있다.
  완화하려면 크기·개수 의존 피처를 빼고 재학습해야 한다.
- 첫 평가 시점(Stage1 첫 트리거)의 동적 점수는 낮고(수집 악성 PID 38개 중 7개가
  0.5 이상, 인샘플 측정), 관찰 창에서 이벤트가 쌓여야 올라간다. 탐지에는 수 초가 걸린다.
- 런타임 검증은 소규모(시뮬레이터 1회, 정상 작업 수십 PID)이며, 실제 랜섬웨어
  샘플을 GuardFS 탐지 모드에서 돌려 본 결과가 아니다.
- 학습에 쓴 악성은 11개 패밀리 38 run이다. moneymessage(부분감염)는 미탐이다.
