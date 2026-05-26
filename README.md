# 엔드포인트 위협 대응을 위한 FUSE 기반 실시간 파일 보호 정책 엔진

FUSE 기반 랜섬웨어 탐지 파일시스템

파일 I/O를 인터셉트하여 프로세스별 위험도를 실시간으로 평가하고,  
**Low → Medium → High** 3단계 상태 머신으로 랜섬웨어 행위를 탐지·차단한다.

---

## 아키텍처 개요

```
사용자 프로세스
     │  파일 write / rename / unlink / truncate / ...
     ▼
[FUSE 마운트 포인트: ~/test_mount/]
     │
     ▼
passthrough.py  ──────────────────────────▶  stage1/detector.py
     │  상태 조회/변경                         │  경량 탐지 (엔트로피·빈도·허니팟)
     │                                        │  score ≥ 1 → stage2 큐에 pid 추가
     ▼                                        ▼
medium.py  (MEDIUM 상태 write 처리)      stage2_worker.py
                                              │  ML 평가 (초기 + 1초 주기 재평가)
                                              ▼
                                    ProcState: LOW / MEDIUM / HIGH
```

### 탐지 2단계 파이프라인

| 단계 | 이름 | 역할 |
|------|------|------|
| Stage 1 | 경량 탐지 | 엔트로피·write빈도·허니팟 접근 점수화 → score ≥ 1이면 Stage2 큐 등록 |
| Stage 2 | ML 평가 | 동적 RF + 정적 RF 앙상블 → MEDIUM / HIGH 판정, 1초 주기 재평가 |

---

## Stage 1: 경량 탐지

세 가지 detector 각각 이벤트를 확인하고, 해당하면 +1점을 부여한다.

| Detector | 탐지 조건 |
|---|---|
| EntropyDetector | write 데이터 Shannon 엔트로피 ≥ 7.0 |
| FrequencyDetector | 단시간 내 write/delete 횟수 임계치 초과 |
| HoneypotDetector | 허니팟 디렉토리(`~/test_mount/honeypot/`) 접근 |

**score ≥ 1** 이면 Stage2 큐에 pid 등록 → ML 평가 시작.

---

## Stage 2: ML 평가

### 모델 구성

| 모델 | 경로 | 입력 피처 |
|---|---|---|
| 동적 RF | `detect_dynamic/dataset/csv_files/best_model.pkl` | PidStats 3-gram 피처 40개 (O/C/D/E 조합) |
| 정적 RF | `final_rf_model.pkl` | ELF 헤더·파일크기·바이트 빈도 등 |

### 점수 계산

```
final_score = 0.5 × dyn_score + 0.5 × stat_score
```

- 정적 점수는 프로세스 생존 중에만 `/proc/pid/exe` 읽어서 계산하고, 캐시에 보관
- 프로세스 종료 후에는 `stat_cache[pid]` 를 재사용 (REEVAL에서도 유효)

### 임계치

| 범위 | 판정 |
|---|---|
| `score < 0.3` | LOW |
| `0.3 ≤ score < 0.82` | MEDIUM |
| `score ≥ 0.82` | HIGH |

### REEVAL (1초 주기 재평가)

MEDIUM 상태의 pid에 대해 매 1초마다 ML을 다시 실행한다.

- 최신 `_pid_features[pid]` (Stage1이 가장 최근에 저장한 동적 피처) 사용
- `stat_cache` 우선 사용 (죽은 프로세스도 처리 가능)
- score ≥ 0.82 → 즉시 HIGH 격상
- 10초 경과 후에도 MEDIUM이면 → LOW 복귀 + 버퍼 커밋

---

## 정책별 동작

### LOW 상태

- write / rename / unlink / truncate 모두 즉시 디스크에 반영
- Stage1 점수 계산 중이면 SUSPICIOUS 를 경유하여 Stage2 큐 등록 후 ML 대기

---

### MEDIUM 상태

의심스럽지만 즉시 차단하지 않고 세 가지 레이어가 병렬 동작한다.

#### 레이어 1: 속도 늦추기 (MTD_DELAY)

| write 누적 횟수 | 추가 지연 |
|---|---|
| 1 ~ 10회 | 없음 |
| 11 ~ 20회 | 100 ms |
| 21회 이상 | 500 ms |

#### 레이어 2: 원본 보존

소용량 파일(< 1 MB): write 요청을 메모리 버퍼에만 보관하고 디스크 원본 유지

| 이후 ML 판정 | 동작 |
|---|---|
| LOW 복귀 (10초 경과) | 버퍼 커밋 전 파일 구조 검증 → 정상이면 디스크에 반영 |
| HIGH 격상 | 버퍼 드롭 → 원본 자동 보존 |
| MEDIUM 유지 | 버퍼 내용 파일 구조 검증 반복 |

파일 구조 검증 기준:

| 확장자 | 검증 조건 |
|---|---|
| `.pdf` | `%PDF-` 헤더 유효 여부 |
| `.docx` / `.xlsx` / `.pptx` / `.zip` | `PK` 구조 유효 여부 |
| `.jpg` | `FF D8 FF` 마커 유효 여부 |
| `.png` | `\x89PNG` 마커 유효 여부 |

구조가 깨진 경우 → 즉시 HIGH 격상

대용량 파일(≥ 1 MB): 메모리 버퍼 없음, MTD_DELAY로 ML 판단 시간 확보.

#### 레이어 3: 지속 감시 및 HIGH 격상 트리거

매 1초마다 ML 재평가 → score ≥ 0.82 이거나 파일 구조 깨지면 즉시 HIGH 격상.

이벤트 로그: `~/filesecurity.log` 에 MEDIUM 판정 시각·대상 파일·사유 기록.

---

### HIGH 상태

**모든 파일 조작을 차단하고 프로세스를 일시 정지한다.**

| 동작 | 설명 |
|---|---|
| write 차단 | 실제 디스크에 기록하지 않음 (버퍼 응답만 반환) |
| rename 차단 | 이름 변경 무시 |
| unlink 차단 | 삭제 무시 |
| truncate 차단 | 크기 변경 무시 |
| SIGSTOP 전송 | `os.kill(pid, signal.SIGSTOP)` — 프로세스 실행 일시 정지 |
| 이벤트 로그 | `~/filesecurity.log` 에 PID·프로세스명·대상 파일·동작·차단 사유 기록 |

HIGH 진입 시 MEDIUM에서 보관 중이던 write 버퍼는 전량 드롭되고, 원본 파일이 보존된다.

HIGH 격상 사유 예시:

| 사유 | 의미 |
|---|---|
| `ml_score=0.823` | 초기 ML 점수 ≥ 0.82 |
| `reeval_score=0.835` | REEVAL 중 ML 점수 ≥ 0.82 |
| `magic_mismatch` | 파일 구조 검증 실패 (magic byte 불일치) |
| `magic_mismatch_reeval` | REEVAL 중 파일 구조 검증 실패 |

---

## 파일 구조

```
Capstone/
├── passthrough.py          # FUSE 메인 (이벤트 수집, 상태 관리, write 라우팅)
├── medium.py               # MEDIUM 상태 write 처리 (3개 레이어 구현)
├── high.py                 # HIGH 상태 처리 (차단·SIGSTOP·로깅)
├── stage2_worker.py        # Stage 2 ML 평가 워커 (초기 + 1초 주기 재평가)
├── states.py               # ProcState Enum (LOW / MEDIUM / HIGH / SUSPICIOUS)
├── stage1/                 # Stage 1 경량 탐지 모듈
│   └── detector.py         # EntropyDetector / FrequencyDetector / HoneypotDetector
├── detect_dynamic/dataset/csv_files/best_model.pkl   # 동적 RF 모델
├── final_rf_model.pkl      # 정적 RF 모델
├── test_high_sim.py        # HIGH 시뮬레이션 (랜섬웨어 행위 모방)
└── test_c_medium.c         # 정적 모델용 최소 C 바이너리 (MEDIUM 유도)
```

---

## 환경 설정

### 가상환경 생성 및 패키지 설치

```bash
python3 -m venv venv
source venv/bin/activate
pip install pyfuse3 trio joblib pandas scikit-learn numpy
```

### FUSE 마운트 포인트 및 underlay 디렉토리 생성

```bash
mkdir -p ~/test_mount ~/test_underlay
mkdir -p ~/test_mount/honeypot
```

---

## 실행 방법

### 1. 가상환경 활성화

```bash
source venv/bin/activate
```

### 2. GuardFS 마운트 (터미널 1)

```bash
python3 passthrough.py ~/test_mount ~/test_underlay
```

마운트 성공 시 `~/test_mount/` 에 파일을 쓰면 GuardFS가 인터셉트한다.  
실제 데이터는 `~/test_underlay/` 에 저장된다.

### 3. 언마운트 (터미널 2 — 종료 시)

```bash
fusermount -u ~/test_mount
```

---

## 테스트 방법

GuardFS를 마운트한 상태에서 **별도 터미널**에서 실행한다.

---

### 테스트 1: LOW — 일반 파일 쓰기

```bash
echo "hello world" > ~/test_mount/hello.txt
```

**예상 동작:**

- Stage1 score = 0 (엔트로피 낮음, 빈도 낮음, 허니팟 아님)
- Stage2 큐 등록 안 됨
- 즉시 디스크에 기록

**예상 로그 (터미널 1):**
```
[WRITE] pid=XXXX state=LOW path=.../hello.txt
```

---

### 테스트 2: MEDIUM — 허니팟 접근 (ML 점수 0.3 ~ 0.82)

```bash
echo "trap" > ~/test_mount/honeypot/trap.txt
```

**예상 동작:**

1. HoneypotDetector 탐지 → score ≥ 1 → Stage2 큐 등록
2. ML 평가: dyn 낮음 + stat 높음 → score ≈ 0.55 ~ 0.82 → MEDIUM
3. write 버퍼 보관, MTD_DELAY 적용
4. REEVAL 10초 동안 MEDIUM 유지 → LOW 복귀 + 버퍼 커밋

**예상 로그 (터미널 1):**
```
[STAGE2] pid=XXXX dyn=0.xxx stat=0.xxx final=0.xxx
[STATE]  pid=XXXX LOW → MEDIUM
[MEDIUM] pid=XXXX path=.../honeypot/trap.txt → 버퍼 보관
[REEVAL] pid=XXXX score=0.xxx elapsed=10.0s
[REEVAL] pid=XXXX 10초 경과 → Low 복귀
```

---

### 테스트 3: HIGH — 랜섬웨어 행위 시뮬레이션

```bash
python3 test_high_sim.py
```

`test_high_sim.py` 는 동일 프로세스(PID) 에서 10회 반복하여 아래 행위를 수행한다:

1. `/dev/urandom` 기반 고엔트로피 데이터 512 B 쓰기 (`E_sum++`)
2. `.txt` → `.enc` 확장자 변경 (`ExtChangeDetector`)
3. 파일 삭제 (`D_sum++`)
4. 0.5초 대기 (REEVAL 사이클 내 누적 가능하도록)

**예상 동작:**

1. 첫 번째 이벤트에서 Stage2 진입 → MEDIUM
2. REEVAL마다 ML 재평가 → `_pid_features` 누적 반영
3. 약 2~4회 REEVAL 후 dyn_score 상승 → score ≥ 0.82 → HIGH 격상
4. 이후 write / rename / unlink 전부 차단, SIGSTOP

**예상 로그 (터미널 1):**
```
[STAGE2] pid=XXXX dyn=0.xxx stat=0.xxx final=0.xxx
[STATE]  pid=XXXX LOW → MEDIUM
[REEVAL] pid=XXXX dyn=0.xxx stat=0.xxx score=0.xxx elapsed=1.0s
...
[REEVAL] pid=XXXX score=0.822 → HIGH 격상
[TRIGGER HIGH] pid=XXXX reason=reeval_score=0.822
[HIGH]   pid=XXXX WRITE BLOCKED path=...
[HIGH]   pid=XXXX suspend 완료
```

HIGH 이벤트는 `~/filesecurity.log` 에도 기록된다.

---

### 테스트 4: 정적 모델 최소 바이너리 (MEDIUM 유도)

```bash
gcc -o test_c_medium test_c_medium.c
./test_c_medium ~/test_mount/c_test.txt
```

**예상 동작:**

- 동적 피처 거의 없음 (write 1회) → dyn_score 낮음
- 정적 모델이 ELF 헤더·바이트 빈도 분석 → stat_score 기반으로 판정
- dyn 낮고 stat 0.5 근처 → score < 0.82 → MEDIUM 또는 LOW

---

## 상태 전이 요약

```
LOW ──(Stage1 score ≥ 1)──▶ SUSPICIOUS ──(ML score ≥ 0.3)──▶ MEDIUM
                                                                   │
                              ┌────────────────────────────────────┤
                              │                                    │
                  (10초 경과, score < 0.3)           (ML score ≥ 0.82  또는
                              │                       magic byte 불일치)
                              ▼                                    ▼
                             LOW                                 HIGH
                                                    (write/rename/unlink/truncate 차단)
                                                    (SIGSTOP + filesecurity.log 기록)
```

| 상태 | write 동작 | rename/unlink | 로깅 |
|---|---|---|---|
| LOW | 즉시 디스크에 쓰기 | 즉시 반영 | 없음 |
| MEDIUM | 버퍼 보관 + MTD_DELAY | 즉시 반영 | `~/filesecurity.log` (MEDIUM 태그) |
| HIGH | 차단 (디스크 기록 안 함) | 차단 | `~/filesecurity.log` (HIGH 태그) + SIGSTOP |

---

## 향후 개선 사항

- 동적·정적 모델 가중치 자동 보정 (학습 데이터 기반)
- HIGH 상태 해제 조건 및 관리자 승인 흐름 추가
- `E_sum` / `D_sum` 누적 임계치 기반 Stage1 score 세분화
- 대용량 파일(≥ 1 MB) 스트리밍 버퍼 지원
- 단위 테스트 확장 (stage2_worker 모킹)
