# HoldFS EDR Dashboard

HoldFS에서 MEDIUM / HIGH로 격상된 프로세스와 그 이유를 실시간으로 보여주고,
AI 보안 분석관(RAG + LLM)에게 자연어로 질의할 수 있는 웹 대시보드.

```text
HoldFS ──(~/filesecurity.log, stdout)──▶ agent.py ──JSON POST──▶ server.py ──▶ 브라우저
                                                                   │
                                                                   └─ /api/chat: 이벤트 + 지식 검색(RAG) → OpenAI
```

HoldFS 코드(`guardfs/`)는 수정하지 않는다. 에이전트가 HoldFS가 이미 남기는 로그를 읽는다.

| 파일 | 역할 |
|---|---|
| `server.py` | Flask 서버. 이벤트 수신/조회 API, 대시보드 페이지, AI 분석 API |
| `agent.py` | HoldFS 로그 tail → JSON 변환 → 서버 전송. `--demo` 샘플 전송 |
| `rag.py` | 이벤트·지식 검색(RAG), LLM 미연결 시 규칙 기반 로컬 분석 |
| `files.py` | 파일 상태 탭: 보호/비보호 폴더 읽기 전용 스캔, 엔트로피 판정 |
| `templates/index.html` | 대시보드 UI |

## 빠른 실행 (권장): `run_all.sh`

```bash
bash dashboard/run_all.sh            # 서버 + HoldFS + 에이전트
bash dashboard/run_all.sh --demo     # + 샘플 이벤트
bash dashboard/run_all.sh --no-guardfs   # HoldFS 없이 화면만 확인
```

- 시작 전에 이전에 떠 있던 서버 / 에이전트 / HoldFS 마운트를 정리한다 (중복 에이전트, 옛 코드로 도는 HoldFS 방지).
- LLM 제공자(Gemini / Groq / OpenAI / 로컬)를 고르고 **API 키를 화면에 보이지 않게 입력**한다.
  키는 파일에 저장하지 않고 서버 프로세스 환경변수로만 전달한다. Enter만 누르면 로컬 모드.
- 로그: `~/guardfs_runtime/dashboard_logs/{server,guardfs_stdout,agent}.log`
- **Ctrl+C 한 번**이면 세 프로세스를 모두 종료하고 마운트를 해제한다.
- 테스트는 다른 터미널에서: `python3 experiments/simulators/sim_highentropy.py ~/guardfs_runtime/mount/sim_target --keep`

아래는 각 구성 요소를 따로 실행하는 방법이다.

## 1. 설치

```bash
cd ~/Capstone            # 저장소 루트
source venv/bin/activate # HoldFS용 venv (없으면 ./scripts/setup.sh)
pip install -r dashboard/requirements.txt
```

## 2. 서버 실행 (터미널 A)

```bash
export OPENAI_API_KEY=sk-...       # 선택. 없으면 '로컬 모드'(규칙 기반 분석)로 동작
export OPENAI_MODEL=gpt-4o-mini    # 선택. 기본값 gpt-4o-mini
python dashboard/server.py --port 5000
```

브라우저에서 http://127.0.0.1:5000 을 연다.
다른 PC에서 접속하려면 `--host 0.0.0.0`으로 실행한다. 인증 기능이 없으므로 신뢰할 수 있는 네트워크에서만 쓴다.

## 3-a. 샘플 이벤트로 바로 확인

```bash
python dashboard/agent.py --demo
```

python3 스크립트형 랜섬웨어 시나리오가 순서대로 전송된다:
MEDIUM 격상 → victim_1~5 WRITE BUFFERED → HIGH 격상(reeval_score=0.837) → BUFFER_DROPPED → SIGSTOP → victim_6 WRITE BLOCKED.
표의 PID를 클릭하거나 우측 빠른 버튼(위협 분석 / ATT&CK 매핑 / 대응 방안 / 패밀리 분석)을 눌러 본다.

## 3-b. 실제 HoldFS와 연동

```bash
# 터미널 B: HoldFS 실행 (stdout을 파일로도 저장해야 격상 이유가 수집된다)
PYTHONUNBUFFERED=1 ./scripts/run_guardfs.sh 2>&1 | tee ~/guardfs_stdout.log

# 터미널 C: 에이전트
python dashboard/agent.py --stdout-log ~/guardfs_stdout.log
```

에이전트가 읽는 로그는 두 종류다.

| 소스 | 내용 | 대시보드 표시 |
|---|---|---|
| `~/filesecurity.log` | `log_medium_event` / `log_high_event` 블록 | WRITE BUFFERED, DELETE BLOCKED, DROP BUFFER_DROPPED, UNLINK STAGED ... |
| `--stdout-log` | `[STAGE2]`, `[WATCH]`, `[REEVAL]`, `[TRIGGER HIGH]`, `[TRUST]`, `[HONEYPOT]` 줄 | `ESCALATE → MEDIUM/HIGH` 행. 탐지 사유에 Stage1 탐지기 + dyn/stat/score + HIGH 사유 표시, `SIGSTOP`, `RETURN → LOW` |

- `PYTHONUNBUFFERED=1`이 없으면 파이프에서 stdout이 버퍼링돼 이벤트가 늦게 들어온다.
- `--stdout-log`를 생략하면 정책 결과(BUFFERED/BLOCKED 등)만 표시되고 격상 행은 나오지 않는다.
- 기존 로그까지 올리려면 `--from-start`를 붙인다.
- 서버가 꺼져 있으면 에이전트가 이벤트를 큐에 보관했다가 서버가 다시 뜨면 재전송한다.

### 강제 상태로 빠르게 시험하기

HoldFS의 테스트용 강제 상태 파일(`/tmp/guardfs_state_<pid>`)을 사용한다.

```bash
MOUNT=~/guardfs_runtime/mount

# MEDIUM: write가 버퍼링된다 → 대시보드에 MEDIUM / WRITE / BUFFERED
bash -c 'echo MEDIUM > /tmp/guardfs_state_$$; for i in 1 2 3; do echo data$i > '"$MOUNT"'/victim_$i.txt; done; sleep 1'

# HIGH: write가 차단되고 프로세스가 SIGSTOP 된다 → HIGH / WRITE / BLOCKED
bash -c 'echo HIGH > /tmp/guardfs_state_$$; echo pwned > '"$MOUNT"'/victim_9.txt' &
sleep 1; kill -9 %1 2>/dev/null   # 정지된 프로세스 정리

rm -f /tmp/guardfs_state_*
```

강제 상태는 ML을 거치지 않으므로 `ESCALATE` 행(격상 이유)은 나오지 않는다.
격상 이유까지 보려면 실제 탐지 시나리오(예: `scripts/run_sample.sh`)를 돌린다.

## 허니팟 접근 표시

HoldFS가 허니팟 접근을 차단하면 출력하는 `[HONEYPOT] pid=… op=… blocked path=…` 줄을 에이전트가 읽어
`SUSPICIOUS / OPEN·UNLINK·RENAME… / BLOCKED` 행으로 표시한다(`--stdout-log` 필요).
허니팟 안 create/mkdir 처럼 차단 없이 관찰되는 접근은 Stage1 `HoneypotDetector` 탐지(`DETECT`) 행으로 표시한다.
같은 PID·동작·경로는 2초 안에 한 번만 표시한다. 이벤트 표의 **허니팟** 필터로 모아 볼 수 있다.

## 파일 상태 탭

왼쪽 📁 탭에서 두 폴더를 나란히 비교한다 (2초마다 갱신, 읽기 전용).

| 폴더 | 기본 경로 | 환경변수 |
|---|---|---|
| 보호 폴더 (HoldFS underlay) | `~/guardfs_runtime/underlay` | `DASH_PROTECTED_DIR` |
| 보호 없는 폴더 (비교용) | `~/guardfs_demo/unprotected` | `DASH_UNPROTECTED_DIR` |

- 파일 앞부분 4KB 엔트로피가 HoldFS 기준(`ENTROPY_THRESHOLD`, 7.0) 이상이면 "암호화 의심", 64B 미만은 "판정 불가".
- `.locked` / `.enc` 등은 "의심 확장자"로 표시. 숨김 파일, 심볼릭 링크는 제외.
- 보호 폴더의 `honeypot/` 파일은 "🍯 미끼 파일"로 목록 맨 위에 따로 표시하고, 정상/암호화 개수에서는 뺀다.
- 시연: 같은 시뮬레이터를 두 경로에 각각 실행한다.
  ```bash
  python3 experiments/simulators/sim_highentropy.py ~/guardfs_runtime/mount/sim_target --keep      # 보호
  python3 experiments/simulators/sim_highentropy.py ~/guardfs_demo/unprotected/sim_target --keep   # 비보호
  ```
  보호 폴더는 반드시 **마운트 경로**로 실행해야 HoldFS가 개입한다(탭은 그 결과가 저장되는 underlay를 보여준다).

## API

| 메서드 | 경로 | 설명 |
|---|---|---|
| POST | `/api/events` | 이벤트 수신. 객체 하나 또는 배열 |
| GET | `/api/events?since_id=N&gen=G` | 증분 조회 + 통계 |
| DELETE | `/api/events` | 이벤트 전체 삭제 |
| POST | `/api/chat` | `{"message": "...", "history": [...]}` → `{"reply", "mode", "sources"}` |
| GET | `/api/files` | 파일 상태 탭: 두 폴더 스캔 결과 |
| GET | `/api/files/preview?folder=&path=` | 파일 앞부분 미리보기 (텍스트 또는 hex) |
| GET | `/api/health` | LLM 연결 여부 |

이벤트 JSON 예:

```json
{
  "time": "2026-05-26 04:00:23",
  "level": "HIGH",
  "pid": 905425,
  "process": "python3",
  "target": "/home/user/guardfs_runtime/underlay/victim_6.txt",
  "action": "WRITE",
  "result": "BLOCKED",
  "reason": "reeval_score=0.837"
}
```

직접 보내 보기:

```bash
curl -X POST http://127.0.0.1:5000/api/events -H 'Content-Type: application/json' \
  -d '{"level":"HIGH","pid":1234,"process":"evil","target":"/tmp/a.docx","action":"WRITE","result":"BLOCKED","reason":"ml_score=0.910"}'
```

## AI 분석관 동작 방식 (RAG)

1. 질문에 PID나 파일명이 있으면 그 이벤트를, 없으면 위험도 높은 PID부터 검색한다.
2. PID별로 요약(격상 타임라인, 동작/결과 통계, 대상 파일, 사유)을 만든다.
3. 사유·동작 키워드로 지식 베이스(HoldFS 정책, 격상 사유 의미, MITRE ATT&CK, 랜섬웨어 패밀리, 대응 절차)에서 관련 문서를 고른다.
4. 이렇게 고른 근거를 시스템 프롬프트와 함께 LLM에 보낸다. 응답 하단에 참조한 PID / 이벤트 수 / 지식 문서가 표시된다.

`OPENAI_API_KEY`가 없거나 LLM 호출이 실패하면 같은 근거로 규칙 기반 보고서를 만든다(우측 상단 `● 로컬 모드`).
이벤트는 서버 메모리에만 저장되므로 서버를 재시작하면 사라진다.
