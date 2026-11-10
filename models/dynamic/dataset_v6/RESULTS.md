# 동적 모델 v6 — 데이터 재수집과 평가 결과

v5 데이터셋의 한계(미끼 환경 고정, 랜덤 미끼 내용, 근접 중복 표본, 약한 감염 run)를
고치기 위해 정상·악성 데이터를 **같은 무작위 미끼 생성기**로 다시 모으고,
계열 단위로 평가한 결과다. 피처 22개와 집계 방식(FUSE-only, PID 단위)은 v5와 같다.

## 1. v5에서 바꾼 것

| 항목 | v5 | v6 |
|---|---|---|
| 미끼 환경 | 파일 20개, 디렉터리 1개 고정 | run마다 시드로 무작위: 파일 50~2000(로그 균등), 깊이 1~4, 2KB~1MB, run당 최대 100MB |
| 미끼 내용 | 짧은 헤더 + 64KB 랜덤 데이터(이미 고엔트로피) | 실제 포맷 위주 저엔트로피 파일(txt/csv/pdf/log …) + 원래 압축된 포맷 일부(docx/xlsx/png/zip) |
| 정상/악성 미끼 | 서로 다른 조건 | **같은 생성기·같은 분포** (`decoy_gen.py`) |
| 라벨 대상 PID | FUSE 로그의 모든 PID | eBPF lineage로 **워크로드 계통만** (`--workload-only`): 미끼 생성기·하네스·데스크톱 데몬 제외 |
| 확장자 변경 rename | 확장자가 다르면 모두 | **v6 규칙**: 임시파일→원래이름 rename(rsync, sed -i, git, 편집기)과 확장자 제거(shred) 제외 (`--ext-rule v6`) |
| 학습 가중치 | `class_weight=balanced` | **run 균형**: run마다 정상 가중치 합을 같게 + 정상/악성 합을 같게 |
| 평가 | 5-fold, 패밀리 단위 LOFO | **계열 단위** LOLO, 계열·워크로드 그룹 CV, **사전 분리한 holdout** |

## 2. 데이터

### 정상 — `features_benign_v6.csv`
- 워크로드 31종 × 3 run + 시험 3 run = **96 run, 3306 PID** (워크로드 계통만)
- 시드 100000~ (`run_benign.py --decoy random`)
- PID 쏠림: openssl/base64/gpg/gcc가 PID의 약 84% → run 균형 가중치로 보정

### 악성 — `features_malware_train_v6.csv`, `features_malware_holdout_v6.csv`, `malware_runs.csv`
- v5에서 실행에 성공한 38개 샘플을 같은 순서로 재수집, 시드 200000~200037
  (`run_sample.sh … --decoy-seed N --timeout 600`)
- **holdout(학습·튜닝에 미사용)**: INCRansom 4, RansomEXX 2 — 수집 전에 지정
- **train**: 9개 패밀리 32 run. MoneyMessage 1 run은 해시상 미끼 전부 변경이지만 FUSE 로그의
  악성 PID 활동이 13 events로 실제 변경과 맞지 않아 **학습 제외(보류)**

| 등급(미끼 중 바뀐 비율) | train | holdout |
|---|---|---|
| full (≥90%) | 21 | 4 |
| partial (10~90%) | 5 | 2 (RansomEXX, 수동 종료 시점 31%) |
| weak (<10%) | 6 (Babuk 계열 5, Conti 1) | – |

v5 대비: Babuk 계열이 건드린 파일 2~14개 → 14~234개, 같은 패밀리 run끼리 피처가 거의 같던
근접 중복이 사라짐(AvosLocker v5 5 run 전부 파일 21개·1.32MB → v6 57~1069개, 6~93MB).

### 계열 묶음
공개 보고(Monti←Conti 유출 코드, Buhti Linux←Babuk)와 수집 관찰(BrainCipher·Conti 일부의
Babuk 동일 패턴)에 근거: **Babuk 계열**(Babuk, BrainCipher, Buhti), **Conti 계열**(Conti, MONTI),
AvosLocker, HelloKitty, REvil.

## 3. 결과 (`eval_v6.py`)

### 계열 단위 평가 (train 31 run, 임계값 0.6)

| 지표 | v5 규칙 피처 | **v6 규칙 피처** |
|---|---|---|
| Leave-One-Lineage-Out 탐지 | 26/31 | **27/31** |
| 계열·워크로드 그룹 CV 탐지 (3회 평균, 0.5 기준) | 30~31/31 | **31/31** |
| 오탐 PID (0.5 기준) | 19~24 / 3306 | **3~7 / 3306** |
| 정상 최고 점수 | 0.89~0.91 | **0.53~0.60** |

- LOLO 미탐 4개는 모두 Babuk 계열의 weak/약신호 run(점수 0.26~0.49).
- 정상 워크로드별 최고 점수(v6): shred_delete 0.58, rsync_mirror 0.51, rename_ext 0.45.
  v5 규칙에서는 rsync_mirror 0.90, shred_delete 0.77, sed_inplace 0.70였다.

### 임계값 (v6, 계열·워크로드 그룹 CV 3회 평균)

| 임계값 | 탐지 | 오탐 run | LOLO 탐지 |
|---|---|---|---|
| 0.50 | 31.0/31 | 5.0/96 | 27/31 |
| 0.55 | 30.3/31 | 2.0/96 | 27/31 |
| **0.60 (확정)** | **29.7/31** | **0.3/96** | **27/31** |
| 0.65 | 27.7/31 | 0.0/96 | 27/31 |

holdout을 보기 전에 **0.6으로 확정**했다.

### holdout (처음 보는 패밀리 2종, 1회 평가)

| run | 점수 | 판정 |
|---|---|---|
| incransom ×4 | 1.000 | 탐지 |
| ransomexx_08113ca0 | 0.573 | 미탐 |
| ransomexx_196eb5bf | 0.588 | 미탐 |
| **합계** | | **4/6** |

- RansomEXX 2개는 임계값 바로 아래이며, 수집 시 수동 종료 시점에 미끼의 31%만 감염된 run이다.
- 학습 시드만 바꾼 모델(0/1/2)로는 6/6, 4/6, 4/6 — **경계에서 결과가 흔들린다.**
- 참고: v5 데이터로 같은 설정 재학습한 모델은 같은 holdout에서 INCRansom 0.60~0.76,
  RansomEXX 0.41~0.47(0.5 기준 4/6). v6 모델이 6개 모두에서 점수가 높다.
- 임계값을 holdout 결과를 보고 바꾸지 않았다(0.5였다면 6/6).

### 상위 피처 (v6, run 균형 가중치)
`distinct_ext_after_rename`, `ext_change_rename_ratio`, `rename_per_sec`, `rename_ratio`,
`read_then_overwrite_ratio`, `mean_write_bytes`, `mean_write_entropy`, `high_entropy_write_ratio`.
v5 상위권이던 규모 피처(`total_write_bytes`, `files_per_dir`, `high_entropy_write_count`)는
하위권으로 내려갔다.

## 4. 한계

- 악성이 train 31 + holdout 6 run으로 적다. 수치는 샘플 몇 개에 따라 움직인다.
- 상위 피처가 rename/확장자 중심이다. 수집된 패밀리가 모두 "암호화 후 확장자 변경" 방식이라
  확장자를 바꾸지 않는 제자리 암호화는 놓칠 수 있다(MoneyMessage는 라벨 문제로 평가 불가).
- 정상 작업 중 `rename_ext`(확장자 일괄 변경), `shred_delete`는 여전히 점수가 0.45~0.58로 높은 편이다.
- 정상 데이터는 합성 워크로드다. 실사용 트레이스로 오탐을 확인하지 않았다.
- holdout에 정상 데이터가 없어 holdout 오탐률은 측정하지 않았다(그룹 CV 오탐률로 대신).

## 5. 배포 작업 현황

1. **런타임 피처 정합 — 완료** (`f1dec18`): `passthrough.py`의 `PidStats`와 학습 추출기
   (`features.py`)가 같은 확장자 판정 규칙(`guardfs/common/ext_rule.py`)을 쓴다.
   규칙은 `config.DYNAMIC_EXT_RULE = "v6"`로 모델과 짝을 맞춘다.
2. **모델 파일 — 완료** (`1af0fb1`, `5af2be0`): `train_v6.py`로 GuardFS venv(scikit-learn 1.3.2)에서
   RandomForest(n_estimators=400, random_state=42), run 균형 가중치로 학습한 `rf_model_v6.pkl`을
   런타임 모델로 전환했다. dyn-only HIGH 임계값은 0.6(`STAGE2_DYN_ONLY_HIGH_THRESHOLD`).
   메타데이터는 `train_v6_meta.json`.
3. **남은 작업**: 경계에서 흔들리는 문제(트리 수·시드 평균 등)는 **새 평가 데이터로** 검증한다.
   이번 holdout으로 다시 튜닝하지 않는다.

## 6. 재현

```bash
# 피처 추출 (원시 로그 → PID 단위 CSV)
python3 models/dynamic/collect/extract_perpid_fuse.py \
    --collect-dir <정상 로그 폴더> --labels <benign_runs_b.csv> \
    --workload-only --ext-rule v6 --out models/dynamic/dataset_v6/features_benign_v6.csv
python3 models/dynamic/collect/extract_perpid_fuse.py \
    --collect-dir <악성 train 로그 폴더> --labels <labels.csv> \
    --workload-only --ext-rule v6 --out models/dynamic/dataset_v6/features_malware_train_v6.csv

# 평가 (holdout은 모델·임계값 확정 후 --holdout 으로 1회)
python3 models/dynamic/collect/eval_v6.py --data models/dynamic/dataset_v6
python3 models/dynamic/collect/eval_v6.py --data models/dynamic/dataset_v6 --holdout
```

위 수치는 scikit-learn 1.9.1에서 계산했다. 1.3.2(VM venv)에서는 소수점이 조금 다를 수 있다.

## 7. 런타임 검증 (VM, GuardFS 실제 마운트)

v6 모델(rf_model_v6.pkl, ext_rule=v6, dyn-only HIGH 0.6)을 GuardFS에 올려 마운트 위에서 확인한 결과다.

### 정상 작업 (오탐 없음)

| 작업 | Stage 2 진입 | 최고 dyn | 결과 |
|---|---|---|---|
| 파일 생성·읽기·rename·삭제 (기본 회귀) | 비신뢰 프로세스라 MEDIUM 선제 적용 | 0.000 | 10초 후 커밋, LOW 복귀 |
| `sed -i` 30개 파일 | Stage 1 미탐지 | – | LOW 유지 |
| `rsync` 텍스트 30개 | Stage 1 미탐지 | – | LOW 유지 |
| `rsync` 고엔트로피 64KB×30 (임시파일→원래 이름) | EntropyDetector | 0.025 | LOW 복귀 |
| `shred -u` 11개 | EntropyDetector | 0.022 | LOW 복귀 |

- 고엔트로피 rsync 패턴을 오프라인에서 재현하면 같은 v6 모델로 v5 확장자 규칙 피처는 0.655(HIGH 차단),
  v6 규칙 피처는 0.065다. 런타임 확장자 규칙을 v6로 맞추지 않으면 정상 rsync가 차단된다.

### 공격 시뮬레이션

| 시나리오 | 결과 | 차단 주체 |
|---|---|---|
| `sim_highentropy.py` (.txt 덮어쓰기 + .locked) | 첫 파일에서 HIGH | MEDIUM 엔트로피 규칙 (PLAIN_TEXT 6.5) |
| 같은 시나리오, rename 없음 | 첫 파일에서 HIGH | MEDIUM 엔트로피 규칙 |
| .png 전체 덮어쓰기 + .x7k2 rename | 두 번째 파일에서 HIGH | MEDIUM magic number 검사 (dyn 0.04→0.215 상승 중) |
| **.png 헤더 8바이트 보존 + 본문 덮어쓰기 + .x7k2 rename** | **미탐: 30개 전부 반영** | 없음 |

마지막 시나리오:
- dyn이 0.24 → 0.48로 계속 올랐지만 0.6에 못 미쳤다. 오프라인 재현 점수는 v6 0.51, v5 0.39라
  v5였어도 미탐이다(v5 임계값 0.5). v6 회귀가 아니라 학습 분포 밖 패턴(읽기 비율 0.89,
  파일당 쓰기 1회)에 대한 경계 점수다. holdout RansomEXX(0.52~0.57)와 같은 유형의 약점이다.
- 가중합 0.387로 MEDIUM에 들어갔지만, 10초 관찰이 끝나자 "헤더 정상"으로 판단해 버퍼를 전부 커밋했다.
  헤더를 보존하는 부분 암호화는 현재 MEDIUM 정책으로 막을 수 없다.

### 후속 과제 (이 결과로 임계값을 다시 튜닝하지 않는다)
1. MEDIUM 타임아웃 커밋 조건 보강: MEDIUM 중에 미지 확장자 rename이 여러 파일에서 일어났거나
   dyn이 계속 오르면 커밋을 보류하거나 HIGH로 격상한다 (MEDIUM 정책 작업).
2. v7 데이터: 헤더 보존 부분 암호화, 확장자를 바꾸지 않는 제자리 암호화, 큰 단위 쓰기 1회 + 작은 단위 읽기
   여러 번 패턴을 추가로 수집한다.
