## Low 위험도 정책

### 핵심 원칙

Low는 정상으로 판단된 상태로, 성능을 최우선으로 하여 파일 write를 즉시 디스크에 기록한다.  

---

### write 처리

버퍼링, 지연, 검증 없이 즉시 디스크에 기록한다.

| 항목 | Low | Medium |
|---|---|---|
| 디스크 기록 | 즉시 | 버퍼 보관 후 커밋 |
| Magic 검증 | 없음 | write 시 + 재평가 시 |
| 딜레이 | 없음 | write 횟수에 따라 100~500ms |
| 재평가 | 없음 | 1초 주기 |

---

### MEDIUM → LOW 복귀 시 정리 작업

Stage 2 재평가에서 Low 복귀 판정 시 아래 두 가지 정리를 수행한다.

#### 1. `_queued_stage2` 해제
MEDIUM 진입 시 중복 전송 방지를 위해 PID가 `_queued_stage2`에 등록된다.  
Low 복귀 후에도 남아있으면 같은 PID가 다시 의심 행위를 해도 Stage 2에 올라가지 못한다.  
`discard`로 제거하여 **재탐지가 가능**하도록 한다.

#### 2. `_write_count` 초기화
MEDIUM에서 MTD_DELAY 계산에 사용된 write 카운터를 초기화한다.  
초기화하지 않으면 다음 MEDIUM 재진입 시 이전 카운터가 남아 딜레이 계산이 틀어진다.

---

### 상태 전이에서의 Low 역할

```
LOW ──(Stage 1 이상 감지)──▶ SUSPICIOUS ──(ML score ≥ 0.3)──▶ MEDIUM
 ▲                                                                  │
 │                                                                  │
 └─────────── 10초 경과, score < 0.7 ───────────────────────────────┘
              _queued_stage2 해제 + _write_count 초기화
```

---

### 관련 파일

| 파일 | 역할 |
|---|---|
| `low.py` | Low 정책 구현 (`handle_write_low`, `handle_low_return`) |
| `passthrough.py` | `write()`에서 Low 분기 → `handle_write_low` 호출 |
| `stage2_worker.py` | Low 복귀 시 `handle_low_return` 호출 |
| `test_low.py` | Low 정책 테스트 스크립트 |

---

## 테스트 방법

### 테스트 3: Low 즉시 디스크 기록 확인 (`test_low.py`)

```bash
python3 test_low.py
```

**동작 흐름:**

1. `low_test_1.txt` write → Low 상태에서 즉시 디스크 기록 확인
2. 고엔트로피 데이터 반복 write → Stage 1 탐지 → MEDIUM 진입
3. 10초 경과 → Low 복귀 + 버퍼 커밋 + 정리 작업
4. 재write → `_queued_stage2` 해제로 재탐지 → MEDIUM 재진입 확인

**예상 로그 (터미널 1):**
```
[WRITE] pid=XXXX state=ProcState.LOW path=.../low_test_1.txt
[STAGE1] pid=XXXX entropy=7.xx reason=EntropyDetector
[STATE] pid=XXXX LOW → MEDIUM
[MEDIUM] pid=XXXX → 버퍼 보관
...
[REEVAL] pid=XXXX 10초 경과 → Low 복귀
[STATE] pid=XXXX MEDIUM → LOW
[COMMIT] pid=XXXX → 커밋 완료
[LOW] pid=XXXX 복귀 정리 완료 (queued_stage2 해제, write_count 초기화)
[STATE] pid=XXXX LOW → SUSPICIOUS
[STATE] pid=XXXX SUSPICIOUS → MEDIUM
```
