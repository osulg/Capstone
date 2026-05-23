# GuardFS

FUSE 기반 랜섬웨어 탐지 파일시스템

파일 I/O를 인터셉트하여 프로세스별 위험도를 실시간으로 평가하고,  
**Low → Medium → High** 3단계 상태 머신으로 랜섬웨어 행위를 탐지·차단한다.

---

## 아키텍처 개요

```
사용자 프로세스
     │  파일 write/read/create/...
     ▼
[FUSE 마운트 포인트: ~/test_mount/]
     │
     ▼
passthrough.py  ─── 이벤트 채널 ───▶  stats_collector
     │                                     │  Stage1 경량 탐지
     │                                     ▼
     │                               stage2_worker
     │  상태 조회/변경                      │  ML 평가 또는 재평가 (1초 주기)
     ▼                                     ▼
medium.py  (MEDIUM 상태 write 처리)   ProcState: LOW / MEDIUM / HIGH
```

- **Stage 1**: 엔트로피, write/delete 빈도 기반 경량 탐지 → SUSPICIOUS 승격
- **Stage 2**: ML 모델 기반 정밀 평가 → MEDIUM / HIGH 판정
- **medium.py**: MEDIUM 판정 시 3개 레이어(속도 늦추기 / 원본 보존 / 지속 감시) 동작

---

## Medium 위험도 정책

### 핵심 원칙

Medium은 **정상일 수도 있는 의심 상태**로, 즉시 차단하지 않고 다음 3가지를 수행한다.

- 원본 파일 보존
- 시간 벌기 (ML이 재판단할 시간 확보)
- 지속 감시

트리거 발생 시 즉시 High 격상, T초 내 트리거 없으면 Low 복귀.  
Medium 판정 즉시 ML 재평가 주기를 5초 → 1초로 단축하고 3개 레이어가 병렬 동작한다.

---

### 레이어 1: 속도 늦추기 (MTD_DELAY)

정상 프로세스는 write 빈도가 낮다는 특성을 이용한 동적 지연.

| write 빈도 | 지연 |
|---|---|
| 1 ~ 10회 | 없음 |
| 11 ~ 20회 | 100ms 지연 |
| 21회 이상 | 500ms 지연 |

---

### 레이어 2: 원본 보존

#### 소용량 파일 (< 1 MB) — 인메모리 버퍼링

`write()` 요청을 메모리 버퍼에만 보관하고 디스크 원본을 유지한다.

| ML 판정 | 동작 |
|---|---|
| 정상 판정 | 버퍼 커밋 전 파일 구조 검증 수행 후 디스크에 반영 |
| 악성 판정 | 버퍼 드롭, 원본 자동 보존 |
| 계속 Medium | 버퍼 내용 파일 구조 검증 |

파일 구조 검증 기준:

| 확장자 | 검증 조건 |
|---|---|
| `.pdf` | `%PDF-` 헤더 유효 여부 |
| `.docx` / `.xlsx` / `.pptx` / `.zip` | `PK` 구조 유효 여부 |
| `.jpg` | `FF D8 FF` 마커 유효 여부 |
| `.png` | `\x89PNG` 마커 유효 여부 |

구조가 깨진 경우 → 즉시 High 격상

#### 대용량 파일 (≥ 1 MB)

메모리 버퍼링이 불가하므로 MTD_DELAY로 ML 판단 시간을 확보한다.  
(실제 파일의 약 90%는 1 MB 이하)  
High 격상 시 즉시 OBF(Obfuscation Block Filter) 적용.

#### 버퍼 자료구조 (병렬 요청 처리)

```python
self._write_buffer: Dict[int, list] = defaultdict(list)
# pid → [(fd, off, buf, path), ...]
```

- **다중 파일 동시 요청**: 동일 PID의 여러 파일 write는 같은 PID 버퍼에 순서대로 누적
- **다른 PID**: 별도 버퍼로 독립 관리
- **동일 파일 다중 write**: 오프셋(off)이 다르므로 순서대로 커밋하면 올바르게 저장됨

```
pid=1234: [(test_1.txt, off=0), (test_2.txt, off=0)]
pid=5678: [(test_3.txt, off=0), (test_4.txt, off=0)]
```

---

### 레이어 3: 지속 감시 및 High 격상 트리거

매 1초마다 실행:

1. 모든 Medium PID 위험도 재계산
2. 높은 점수 순으로 정렬 후 재평가
3. 임계치(0.7) 초과 PID → 즉시 High 격상
4. 임계치 미만 PID → Medium 유지 + 버퍼 구조 검증 반복
5. 점수 낮아진 PID → Low 복귀 + 버퍼 커밋

---

### 현재 구현 상태 (테스트 모드)

실제 ML 모델 연동 전, 동작 확인을 위해 아래와 같이 임의 점수를 주입하고 있다.

- **고정 위험 점수 0.5** → 모든 write가 MEDIUM 상태로 진입
- **10초 경과** → 트리거 없으면 자동으로 Low 복귀 + 버퍼 커밋

관련 코드: [stage2_worker.py:29](stage2_worker.py#L29), [passthrough.py:277](passthrough.py#L277)

---

## 파일 구조

```
Capstone/
├── passthrough.py     # FUSE 메인 (이벤트 수집, 상태 관리, write 라우팅)
├── medium.py          # Medium 상태 write 처리 (3개 레이어 구현)
├── stage2_worker.py   # Stage 2 ML 재평가 워커 (1초 주기)
├── states.py          # ProcState Enum (LOW / MEDIUM / HIGH / SUSPICIOUS)
├── stage1/            # Stage 1 경량 탐지 모듈
├── test.py            # 기본 쓰기 테스트 (Medium → Low 복귀 확인)
└── test2.py           # PDF 헤더 검증 테스트 (정상/깨진 PDF)
```

---

## 환경 설정

### 가상환경 생성 및 패키지 설치

```bash
python3 -m venv venv
source venv/bin/activate
pip install pyfuse3 trio joblib pandas
```

### FUSE 마운트 포인트 및 underlay 디렉토리 생성

```bash
mkdir -p ~/test_mount ~/test_underlay
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

GuardFS를 마운트한 상태에서 **별도 터미널**에서 테스트 스크립트를 실행한다.

### 테스트 1: Medium → Low 복귀 확인 (`test.py`)

```bash
python3 test.py
```

**동작 흐름:**

1. `~/test_mount/` 에 `test_1.txt`, `test_2.txt`, `test_3.txt` 순서로 쓰기
2. 각 write마다 강제로 MEDIUM 상태 진입 (score=0.5 고정)
3. write 내용은 메모리 버퍼에만 보관 (`[MEDIUM] ... → 버퍼 보관` 로그 출력)
4. 10초 경과 후 자동으로 LOW 복귀 + 버퍼 커밋 (`[REEVAL] ... 10초 경과 → Low 복귀`)

**예상 로그 (터미널 1):**
```
[STATE] pid=XXXX LOW → MEDIUM
[WRITE] pid=XXXX state=MEDIUM path=.../mnt/test_1.txt
[MEDIUM] pid=XXXX path=.../mnt/test_1.txt off=0 size=1200 → 버퍼 보관
...
[REEVAL] pid=XXXX score=0.500 elapsed=10.0s
[REEVAL] pid=XXXX 10초 경과 → Low 복귀
[COMMIT] pid=XXXX path=.../mnt/test_1.txt off=0 → 커밋 완료
```

---

### 테스트 2: PDF 헤더 검증 (High 격상) (`test2.py`)

```bash
python3 test2.py
```

**동작 흐름:**

1. 정상 PDF(`%PDF-` 헤더) 쓰기 → 버퍼 보관 후 정상 커밋
2. 깨진 PDF(헤더 없음) 쓰기 → magic number 불일치 감지 → 즉시 High 격상

**예상 로그 (터미널 1):**
```
[MEDIUM] pid=XXXX path=.../test_normal.pdf off=0 size=22 → 버퍼 보관
[MEDIUM] pid=XXXX path=.../test_broken.pdf magic number 불일치 → High 격상
[TRIGGER HIGH] pid=XXXX reason=magic_mismatch
[STATE] pid=XXXX MEDIUM → HIGH
```

---

### 수동 테스트 (마운트 포인트에 직접 파일 쓰기)

```bash
# 일반 텍스트 쓰기
echo "test content" > ~/test_mount/hello.txt

# 정상 PDF 쓰기
python3 -c "open(os.path.expanduser('~/test_mount/test.pdf'),'wb').write(b'%PDF-1.4 content')"

# 대용량 파일 쓰기 (1 MB 이상 → MTD_DELAY 경로)
dd if=/dev/urandom of=~/test_mount/large.bin bs=1M count=2

# underlay 비우기 (테스트 재실행 전)
rm -f ~/test_underlay/*
```

---

## 상태 전이 요약

```
LOW ──(anomaly detected)──▶ SUSPICIOUS ──(ML score ≥ 0.3)──▶ MEDIUM
                                                                 │
                              ┌──────────────────────────────────┤
                              │                                  │
                   (10초 경과, score < 0.3)          (score ≥ 0.7 또는 magic 불일치)
                              │                                  │
                              ▼                                  ▼
                             LOW                               HIGH
```

| 상태 | write 동작 |
|---|---|
| LOW | 즉시 디스크에 쓰기 |
| MEDIUM | 버퍼 보관 + MTD_DELAY + 1초 주기 재평가 |
| HIGH | write 차단 (OBF 적용) |
