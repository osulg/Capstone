# GuardFS 동적 탐지 모델 — 성능 결과 (dataset_v4)

FUSE(GuardFS) + eBPF로 수집한 프로세스 행동 데이터로 랜섬웨어를 탐지한 결과.

## 데이터셋

- **총 286 샘플** = 정상(benign) 248 + 악성(ransomware) 38
- 악성 **11개 패밀리**: avoslocker, babuk, braincipher, buhti, conti,
  hellokitty, incransom, monti, moneymessage, ransomexx, revil
- 정상 **31종 워크로드** (bulk copy/delete, tar/gzip, sqlite, git, gpg,
  random write, rename 등) × 파일수 × 크기 × 반복
- 수집 관점: eBPF(syscall) + FUSE(파일 연산·엔트로피) **동일 스키마**
- 피처 **24개** (프로세스 단위): 연산 속도/비율, 쓰기 엔트로피,
  read-then-overwrite, 확장자 변경 rename, 확산 범위 등
- 라벨: eBPF process lineage 기반 자동 라벨 (수동 PID 지정 없음)
- 산출물: `features.csv`(피처), `labels.csv`(라벨), `anomaly_report.json`

## 최종 성능

### 1) 지도학습 RandomForest (최종 모델, 5-fold 교차검증)

| 지표 | 값 |
|------|----|
| 탐지율(Recall) | **92.1%** (38개 중 35개) |
| 오탐률(FPR) | **0%** (정상 248개 전부 정상 판정) |
| 정밀도(Precision) | **100%** |
| F1 | **0.96** |
| ROC-AUC | **1.0** |
| 정확도 | 99.0% |

> **"랜섬웨어의 92%를, 헛경보 0건으로 탐지."**

### 2) 일반화 검증 — Leave-One-Family-Out (LOFO)

한 패밀리를 학습에서 완전히 제외하고, 그 **처음 보는 패밀리**를 탐지:

| 패밀리 | 탐지 |
|--------|------|
| babuk, braincipher, buhti, conti, hellokitty, incransom, monti, ransomexx, revil | **100%** (안 봐도) |
| avoslocker | 40% (2/5) |
| moneymessage | 0% (1/1, 부분감염이라 신호 약함) |
| **평균 (안 본 패밀리)** | **89.5%** (34/38) |

→ 본 패밀리 포함(92.1%)과 거의 차이 없음. **외운 것이 아니라 "랜섬웨어 공통 행동"을
  학습해 미지의 패밀리에도 일반화됨**을 입증.

### 3) 반지도 이상탐지 (IsolationForest, 정상만 학습)

라벨 없이 정상 분포만 학습 → 이탈을 이상치로 탐지. FPR–탐지율 트레이드오프:

| 목표 FPR | 실제 FPR | 탐지율 |
|:---:|:---:|:---:|
| 5% | 8.1% | 43.2% |
| 10% | 13.6% | 63.2% |
| 15% | 21.9% | 76.3% |

정상 14개였을 때 FPR 30%±40%로 요동치던 것이 **248개로 8%±5%까지 안정화**.
일부 정상 워크로드(gzip/random_write/gpg)가 고엔트로피 쓰기라 랜섬웨어와 겉보기
유사해 정밀도는 낮다(base-rate 문제). → **정상 데이터 추가 확보가 개선 핵심.**

## 가장 중요한 판별 피처 (RF 중요도 상위)

1. `read_then_overwrite_ratio` — 원본 읽고 암호문 덮어쓰기
2. `ext_change_rename_ratio` — 확장자 바꾸며 rename
3. `high_entropy_write_count` / `high_entropy_write_ratio` — 암호문(고엔트로피) 쓰기
4. `mean_write_bytes` — 큰 청크 쓰기
5. `distinct_ext_after_rename` — rename 후 확장자 다양성

모두 **패밀리 무관한 랜섬웨어 공통 행동** → 일반화의 근거.

## 한계 & 향후 과제

- 못 잡은 3개(avoslocker 일부, moneymessage)는 **실제로 암호화가 약한 run** —
  행동이 정상과 구분되지 않음. 악성 수집을 늘리면 보강 가능.
- 일부 패밀리는 샘플 1~2개라 LOFO 추정이 불안정 → 악성 패밀리 다양화 필요.
- 반지도(이상탐지)는 정밀도가 낮음 → 정상 데이터 대량 확보 시 FPR 추가 개선.

## 재현 방법

```bash
# 1) 수집 로그(ebpf/fuse jsonl) → 피처 CSV
python3 models/dynamic/collect/logs_to_csv.py \
    --collect-dir <collect_dir> --labels labels.csv --out features.csv
# 2) 반지도 이상탐지 학습/평가
python3 models/dynamic/collect/train_anomaly.py \
    --benign-csv benign_features.csv --malware-csv malware_features.csv
# 3) 지도학습/LOFO 평가는 features.csv를 RandomForest로 CV (본 README 수치 산출)
```
