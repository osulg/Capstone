# 엔드포인트 위협 대응을 위한 FUSE 기반 실시간 파일 보호 정책 엔진

FUSE 기반 랜섬웨어 탐지 파일시스템

파일 I/O를 인터셉트하여 프로세스별 위험도를 실시간으로 평가하고,  
**Low → Medium → High** 3단계 상태 머신으로 랜섬웨어 행위를 탐지·차단한다.

---

## 이 브랜치(`feature/medium-policy-hardening`)에서 바뀐 것

`main`의 MEDIUM 정책 코드 리뷰에서 나온 지적사항을 고치고, 그 과정에서 추가로 발견한
버그를 고친 뒤, 논문 근거를 붙여 MEDIUM 정책 규칙 5개를 새로 추가했다. 아래 표는
전부 실측(FUSE 마운트 실동작 테스트 또는 격리된 unit test)으로 검증됨.

### 고친 버그

| # | 문제 | 위치 | 수정 |
|---|---|---|---|
| 1 | 소용량/대용량 파일 판단이 이번 write 크기(`len(buf)`) 기준이라, 파일을 64KB~128KB 단위로 나눠 쓰면 몇 GB짜리 파일도 항상 "소용량"으로 오판 | `medium.py` | `os.fstat(fd).st_size` 기반 파일 전체 누적 크기로 판단하도록 변경 |
| 2 | 메모리 버퍼(`_write_buffer`)에 상한이 없어 같은 프로세스가 계속 write하면 메모리 무제한 증가 | `medium.py` | PID·확장자그룹별 버퍼 상한 + 전역 버퍼 상한(200MB) 추가, 초과 시 즉시 HIGH 격상 |
| 3 | 모든 MEDIUM 프로세스에 동일 지연 적용 (`/bin`의 서명된 바이너리든 `/tmp`의 수상한 스크립트든 구분 없음) | `medium.py` | 프로세스 실행경로 신뢰도(`is_trusted_process`)로 이원화 — 신뢰 경로는 지연 완화·대용량 버퍼링 예외, 비신뢰는 크기 무관 항상 버퍼링 |
| 4 | REEVAL(1초 주기 ML 재평가)과 신규 이벤트 수신이 같은 `while` 루프에서 순차 실행돼, MEDIUM PID가 많으면 신규 탐지가 밀림 | `stage2_worker.py` | `intake_loop`/`reeval_loop`을 독립된 trio 태스크로 분리, 정적모델의 블로킹 파일 I/O는 `trio.to_thread.run_sync`로 오프로드 |
| 5 | Stage1의 3개 탐지기(허니팟/확장자변경/엔트로피)와 PidStats 임계치를 모두 피하면 `mark_suspect`가 절대 호출되지 않아 MEDIUM에 진입할 방법 자체가 없음 | `passthrough.py` | 신규 PID + 비신뢰 실행경로 조합이면 15% 확률로 Stage1 결과와 무관하게 강제로 Stage2 큐 등록 (`STAGE1_SAMPLING_RATE`) |
| 6 | SUSPICIOUS(ML 판정 대기 중) 상태의 write가 무조건 LOW로 취급돼 즉시 디스크 반영 — 판정 나기 전 첫 write가 무방비 | `passthrough.py` | 비신뢰 프로세스는 SUSPICIOUS도 MEDIUM처럼 취급해 판정 전부터 선제 버퍼링 (신뢰 경로는 기존대로 LOW 유지) |
| 7 | (신규 발견) `predict_dynamic()`이 `StandardScaler` 없이 원본 카운트값을 그대로 RandomForest에 넣고 있었음 — 학습은 정규화된 값으로 했는데 추론은 원본 값으로 함 | `stage2_worker.py` | `scaler.pkl` 로드해서 추론 전 `transform()` 적용. bash로 파일 1개 write한 케이스에서 dyn 점수가 0.870→0.184로 정상화됨을 확인 |
| 8 | (신규 발견) MEDIUM 상태에서도 기존 파일을 `O_TRUNC`로 열면(`open(path,'w')`) `os.open()` 순간 실제 파일이 즉시 비워짐 — write 버퍼링과 무관하게 원본 손실 | `passthrough.py` | O_TRUNC open을 실제 경로 대신 스테이징 fd로 유도, 커밋 시점에만 원본에 반영 |
| 9 | (신규 발견) Stage2 초기 판정이 LOW로 나올 때 `_queued_stage2`에서 안 빠져서, 한 번 의심받고 LOW 판정난 프로세스는 이후 진짜 랜섬웨어 행동을 해도 재평가 큐에 다시 못 들어감 | `stage2_worker.py` | 초기 LOW 판정 분기에도 `commit_buffers` + `handle_low_return` 호출 추가 |
| 10 | `trigger_high()` 호출 경로(즉시 격상/REEVAL 중 격상/커밋 실패 시 격상)마다 정리 로직이 제각각 — 전역 버퍼 카운트 감소나 unlink 복원이 누락되는 경로 존재 | `high.py`, `medium.py` | 모든 HIGH 진입 정리를 `medium.drop_buffers()` 하나로 통합, `handle_high_enter`는 이를 호출만 함 |

### 임계값 재계산 (F)

버그 7 수정 후, 동적 모델 held-out 테스트셋(253개, 악성 22개) 기준으로 `cost = 5×FN + 1×FP`
비용함수 스윕 실시. **MEDIUM 임계값(0.3)은 이미 비용 최소 지점**이라 변경 안 함.
HIGH(0.82)는 0.70~0.80이 근소하게 낫지만 근거 표본이 1개 차이라 약함 — 데이터 더
모은 뒤 재검토하기로 보류.

### 새로 추가한 MEDIUM 규칙

| # | 규칙 | 내용 | 근거 |
|---|---|---|---|
| 1 | 확장자 그룹별 보호 강도 차등 | 파일을 `HIGH_VALUE`(문서·DB·키)/`COMPRESSED`(미디어)/`PLAIN_TEXT`/`UNKNOWN` 4그룹으로 나눠 버퍼 상한·지연 배율·엔트로피 임계값을 다르게 적용 | Taylor et al., "The Inadequacy of Entropy-Based Ransomware Detection", **ICONIP 2019**(원 제안서엔 NDSS로 잘못 인용돼 있어 정정) — 압축 포맷은 암호화 후에도 엔트로피 증가폭이 작아 단일 임계값으로 탐지 어려움. NetApp ONTAP ARP의 확장자군별 차등 정책 |
| 2 | magic byte를 넘어선 구조 검증 | 커밋 직전 해당 경로의 버퍼된 조각을 메모리에서 재조합해 ZIP 목차(`[Content_Types].xml`)·PDF 트레일러(`%%EOF`)·SQLite 헤더 등 내부 구조까지 검증. HIGH_VALUE 그룹에만 적용 | magic byte만 맞추고 내부를 깨뜨리는 회피에 대응 |
| 3 | 경과시간 기반 지연 재설계 | write "누적 횟수" 대신 MEDIUM 진입 후 "경과시간" 구간(0~2s/2~5s/5s~)별로 지연 적용, 그룹별 배율 곱함 | von der Assen et al., "GuardFS", **arXiv:2401.17917**, Table 6 — DEL+OBF 방어 실측: 1초 지연 평균 손실 3.87MB, 5초 0.7MB, 10초 0.75MB(5초 이후 개선 없음). 논문 수치를 실제 PDF Table 6에서 직접 대조해 확인 |
| 4 | unlink 단계적 차단 | MEDIUM 중 unlink는 실제 삭제 대신 스테이징으로 이동(호출자에겐 성공으로 응답) → LOW 판정 시 삭제 확정, HIGH 격상 시 원본 복원 | Rcryptect, *Computers & Security* 2021의 "의심 단계 진입 후 root만 삭제 허용" 아이디어를, 권한 모델이 없는 우리 구조에 맞게 스테이징+지연확정 방식으로 재설계 |
| 5 | 시스템 전역 버퍼 상한 | PID별 상한과 별개로 전역 200MB 상한을 두고, 초과를 유발한 write의 주체를 즉시 HIGH로 격상 | GuardFS/ShieldFS가 공통으로 지적하는 "버퍼 기반 방어는 동시 프로세스 수에 비례해 메모리 요구량이 느는 DoS 위험" |

### 기존(main) 대비 정책 변화 요약

| 항목 | 기존 | 이 브랜치 |
|---|---|---|
| 버퍼링 여부 판단 기준 | 이번 write 크기 | 파일 전체 누적 크기(`fstat`) |
| 버퍼 상한 | 없음 | PID+확장자그룹별 + 전역 200MB |
| 지연 방식 | write 횟수 기반(10/20회 → 100ms/500ms) | 경과시간 기반(0~2/2~5/5s~), 그룹별 배율 |
| 신뢰도 반영 | 없음 | 실행경로 신뢰도로 버퍼링·지연 이원화 |
| SUSPICIOUS(판정 대기) 상태 | 무조건 LOW 취급 | 비신뢰는 MEDIUM처럼 선제 버퍼링 |
| `open(O_TRUNC)` | 즉시 원본 truncate | 스테이징 유도, 커밋 시에만 반영 |
| unlink | 즉시 삭제(HIGH만 차단) | MEDIUM에서 스테이징 이동 후 지연 확정 |
| Stage1 게이트 | 탐지기 3개뿐 | + 보조 샘플링(15%) |
| 동적 모델 추론 | 스케일러 미적용(버그) | 스케일러 적용 |
| 파일 유형 구분 | 없음(전부 동일 취급) | 확장자 4그룹별 차등 |
| 구조 검증 | magic byte만 | HIGH_VALUE는 내부 구조까지 |

### 모델을 새로 만든다면 — 다음 단계

**왜 필요한가**: 지금 `final_score = 0.5×dyn_score + 0.5×stat_score`인데, 동적 데이터셋
(`malware_dataset.csv`, 1263행 — 프로세스 행동 로그)과 정적 데이터셋
(`merged_topk_balanced_k200.csv`, 90행 — 바이너리 자체)이 같은 샘플을 공유하지 않는다.
그래서 이번 세션의 임계값 재계산(F)도 동적 모델만 검증했고, 앙상블 자체를 하나의
정답 레이블로 제대로 튜닝한 적은 아직 없다.

**새 모델 작업 시 우선순위**:

1. **페어링된 데이터셋 확보** — `sim_ransomware.py` 같은 시뮬레이터로 GuardFS를 실제로
   돌리면서, 같은 프로세스의 동적 피처(PidStats)와 그 프로세스 실행파일의 정적 피처를
   동시에 기록하는 파이프라인부터 만들어야 앙상블 튜닝이 의미가 있다.
2. **확률 보정(calibration)** — RandomForest의 `predict_proba`는 실제 확률이 아니라서,
   지금처럼 0.3/0.82 같은 확률 임계값을 직접 비교하는 게 이론적으로 부정확하다.
   `CalibratedClassifierCV` 등으로 보정한 뒤 임계값을 다시 검증해야 한다.
3. **앙상블 가중치 학습** — 지금 0.5:0.5로 고정된 `DYNAMIC_MODEL_WEIGHT`/`STATIC_MODEL_WEIGHT`를
   로지스틱 회귀 등으로 스태킹해서 데이터 기반으로 재산출.
4. **데이터 불균형 개선** — 동적 데이터셋이 정상 1151 : 악성 112로 치우쳐 있고, 악성 중에서도
   특정 랜섬웨어 계열(`Type` 컬럼 기준 `4dc06` 174개 등)에 쏠려 있다. 다양한 계열 샘플 확충 필요.
5. **정책 하드코딩 값의 피처화** — 지금 `medium.py`에 고정값으로 박아둔 확장자별
   `entropy_threshold`(7.2/6.5/6.8)나 `is_trusted_process` 이원화를, 규칙으로 남기는 대신
   모델 입력 피처로 넣어 학습시키는 것도 검토할 만하다.
6. **교차검증** — 지금 held-out 테스트가 253개 중 악성 22개뿐이라 임계값 스윕 결과가
   표본 노이즈에 민감하다(F 항목에서 이미 확인됨). k-fold로 재검증해서 신뢰도를 높여야 한다.

**모델과 무관하게 남은 일**:

- **HIGH 임계값(0.82) 확정** — 데이터를 더 모은 뒤 F(비용가중 스윕)를 재실행해서 결정
- **`STAGE1_SAMPLING_RATE`(15%)** — 논문 근거 없이 잡은 임시값. ROC 기반으로 재조정 필요
- **`rename()` 핸들러 보호** — 지금은 HIGH만 차단하고 MEDIUM/SUSPICIOUS는 무방비.
  unlink처럼 스테이징으로 유도하는 방식을 적용할 여지가 있음
- **디렉토리 화이트리스트** — `~/Documents` 등 고위험 경로를 강제로 `HIGH_VALUE` 그룹
  취급하는 아이디어(NetApp ARP의 볼륨별 정책에서 착안). 아직 미구현
- **정식 회귀 테스트 편입** — 이번 세션의 검증은 전부 임시 스크립트(`/tmp` 스크래치패드)로
  했다. `experiments/tests/`에 pytest 기반 회귀 테스트로 옮겨야 다음 변경에서도 안전망이 됨

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

## 파일 구조

```
Capstone/
├── guardfs/fuse_fs/
│   └── passthrough.py          # FUSE 메인 (이벤트 수집, 상태 관리, write 라우팅)
├── stage1/                     # Stage 1 경량 탐지 모듈
│   └── detector.py             # EntropyDetector / FrequencyDetector / HoneypotDetector
├── stage2/
│   ├── stage2_worker.py        # Stage 2 ML 평가 워커 (초기 + 1초 주기 재평가)
│   ├── states.py                # ProcState Enum (LOW / MEDIUM / HIGH / SUSPICIOUS)
│   └── policy/
│       ├── medium.py            # MEDIUM 상태 write 처리 (3개 레이어 구현)
│       └── high.py              # HIGH 상태 처리 (차단·SIGSTOP·로깅)
├── detect_dynamic/dataset/csv_files/best_model.pkl   # 동적 RF 모델
├── fused_model/
│   └── final_rf_model.pkl      # 정적 RF 모델
└── tests/
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
python3 guardfs/fuse_fs/passthrough.py ~/test_mount ~/test_underlay
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
python3 tests/test_high_sim.py
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
gcc -o test_c_medium tests/test_c_medium.c
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

모델 관련 계획(가중치 자동 보정, 페어링된 데이터셋 확보 등)은
[모델을 새로 만든다면 — 다음 단계](#모델을-새로-만든다면--다음-단계) 참고.

- HIGH 상태 해제 조건 및 관리자 승인 흐름 추가
- `E_sum` / `D_sum` 누적 임계치 기반 Stage1 score 세분화
- 대용량 파일(≥ 1 MB) 스트리밍 버퍼 지원
- 단위 테스트 확장 (stage2_worker 모킹)
