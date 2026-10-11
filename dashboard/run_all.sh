#!/bin/bash
# ============================================================
# run_all.sh — 대시보드 서버 + GuardFS + 에이전트를 한 번에 실행
#
# - 이전에 떠 있던 서버 / 에이전트 / GuardFS 마운트를 먼저 정리한다
#   (중복 에이전트, 옛 코드로 도는 GuardFS, 깨진 로그 파일 방지)
# - LLM API 키는 실행할 때마다 화면에 보이지 않게 입력받는다.
#   키는 파일에 저장하지 않고 서버 프로세스 환경변수로만 전달한다.
# - Ctrl+C 한 번이면 세 프로세스를 모두 종료하고 마운트를 해제한다.
#
# 사용법:
#   bash dashboard/run_all.sh              # 전체 실행
#   bash dashboard/run_all.sh --demo       # 실행 후 샘플 이벤트도 전송
#   bash dashboard/run_all.sh --no-guardfs # GuardFS 없이 서버+에이전트만 (화면 확인용)
#
# 환경변수:
#   DASH_PORT (기본 5000), DASH_HOST (기본 0.0.0.0)
# ============================================================
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="$PROJECT_ROOT/venv"
RUNTIME_DIR="$HOME/guardfs_runtime"
MOUNT_DIR="$RUNTIME_DIR/mount"
LOG_DIR="$RUNTIME_DIR/dashboard_logs"
PORT="${DASH_PORT:-5000}"
HOST="${DASH_HOST:-0.0.0.0}"

SERVER_LOG="$LOG_DIR/server.log"
GUARDFS_LOG="$LOG_DIR/guardfs_stdout.log"
AGENT_LOG="$LOG_DIR/agent.log"

DEMO=0
NO_GUARDFS=0
for arg in "$@"; do
    case "$arg" in
        --demo)       DEMO=1 ;;
        --no-guardfs) NO_GUARDFS=1 ;;
        -h|--help)    sed -n '2,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "알 수 없는 옵션: $arg (--help 참고)"; exit 1 ;;
    esac
done

SERVER_PID=""; GUARDFS_PID=""; AGENT_PID=""; TAIL_PID=""

say()  { echo "[run_all] $*"; }
fail() { echo "[run_all] ERROR: $*" >&2; exit 1; }

unmount_guardfs() {
    if mountpoint -q "$MOUNT_DIR" 2>/dev/null; then
        fusermount3 -u "$MOUNT_DIR" 2>/dev/null \
            || fusermount3 -uz "$MOUNT_DIR" 2>/dev/null \
            || fusermount -uz "$MOUNT_DIR" 2>/dev/null \
            || true
    fi
}

# 이 스크립트가 띄우지 않은 이전 실행분까지 정리한다.
cleanup_previous() {
    pkill -f "dashboard/agent.py" 2>/dev/null
    pkill -f "dashboard/server.py" 2>/dev/null
    unmount_guardfs
    # 마운트 해제 후에도 남은 GuardFS 프로세스 정리 (SIGSTOP된 테스트 프로세스는 건드리지 않음)
    pkill -f "guardfs/fuse_fs/passthrough.py" 2>/dev/null
    rm -f /tmp/guardfs_state_*
    sleep 1
}

shutdown_all() {
    trap - INT TERM EXIT
    echo ""
    say "종료 중..."
    [ -n "$TAIL_PID" ]   && kill "$TAIL_PID" 2>/dev/null
    [ -n "$AGENT_PID" ]  && kill "$AGENT_PID" 2>/dev/null
    unmount_guardfs                                  # 언마운트되면 GuardFS도 종료됨
    [ -n "$GUARDFS_PID" ] && { sleep 1; kill "$GUARDFS_PID" 2>/dev/null; }
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    rm -f /tmp/guardfs_state_*
    wait 2>/dev/null
    say "모두 종료했습니다. 로그: $LOG_DIR"
    exit 0
}

# ----------------------------------------
# 0. 준비
# ----------------------------------------
cd "$PROJECT_ROOT" || fail "프로젝트 경로로 이동 실패"
[ -d "$VENV_DIR" ] || fail "가상환경이 없습니다. 먼저 ./scripts/setup.sh 를 실행하세요."
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
python -c "import flask" 2>/dev/null || fail "flask가 없습니다: pip install -r dashboard/requirements.txt"
mkdir -p "$LOG_DIR"
# 파일 상태 탭의 '보호 없는 폴더' (비교 시연용, GuardFS를 거치지 않음)
UNPROTECTED_DIR="${DASH_UNPROTECTED_DIR:-$HOME/guardfs_demo/unprotected}"
mkdir -p "$UNPROTECTED_DIR"

say "이전 실행 정리 (서버 / 에이전트 / GuardFS)"
cleanup_previous

# ----------------------------------------
# 1. LLM 설정 (키는 화면에 표시하지 않음)
# ----------------------------------------
echo ""
echo "LLM 제공자를 선택하세요:"
echo "  1) Google Gemini (무료 등급)   [기본]"
echo "  2) Groq (무료 등급)"
echo "  3) OpenAI (유료)"
echo "  4) LLM 없이 로컬 규칙 기반 분석"
read -rp "번호 [1]: " CHOICE
CHOICE="${CHOICE:-1}"

LLM_BASE_URL=""; LLM_MODEL=""
case "$CHOICE" in
    1) LLM_BASE_URL="https://generativelanguage.googleapis.com/v1beta/openai/"; LLM_MODEL="gemini-2.5-flash" ;;
    2) LLM_BASE_URL="https://api.groq.com/openai/v1"; LLM_MODEL="llama-3.3-70b-versatile" ;;
    3) LLM_BASE_URL=""; LLM_MODEL="gpt-4o-mini" ;;
    4) ;;
    *) fail "잘못된 번호: $CHOICE" ;;
esac

LLM_KEY=""
if [ "$CHOICE" != "4" ]; then
    read -rp "모델 이름 [$LLM_MODEL]: " MODEL_IN
    LLM_MODEL="${MODEL_IN:-$LLM_MODEL}"
    read -rsp "API 키 (입력 내용은 표시되지 않음, Enter=로컬 모드): " LLM_KEY
    echo ""
    [ -z "$LLM_KEY" ] && say "키를 입력하지 않아 로컬 모드로 실행합니다."
fi

# ----------------------------------------
# 2. 대시보드 서버
# ----------------------------------------
trap shutdown_all INT TERM EXIT

say "대시보드 서버 시작 (port $PORT)"
if [ -n "$LLM_KEY" ]; then
    # 키는 서버 프로세스에만 전달하고 이 셸에는 남기지 않는다.
    OPENAI_API_KEY="$LLM_KEY" OPENAI_BASE_URL="$LLM_BASE_URL" OPENAI_MODEL="$LLM_MODEL" \
        PYTHONUNBUFFERED=1 python dashboard/server.py --host "$HOST" --port "$PORT" \
        > "$SERVER_LOG" 2>&1 &
else
    env -u OPENAI_API_KEY PYTHONUNBUFFERED=1 \
        python dashboard/server.py --host "$HOST" --port "$PORT" > "$SERVER_LOG" 2>&1 &
fi
SERVER_PID=$!
unset LLM_KEY

for _ in $(seq 1 20); do
    curl -s "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1 && break
    kill -0 "$SERVER_PID" 2>/dev/null || { tail -n 20 "$SERVER_LOG"; fail "서버가 시작되지 않았습니다"; }
    sleep 0.5
done
HEALTH="$(curl -s "http://127.0.0.1:$PORT/api/health")"
say "서버 준비 완료: $HEALTH"

# ----------------------------------------
# 3. GuardFS
# ----------------------------------------
AGENT_ARGS=( --server "http://127.0.0.1:$PORT" )
if [ "$NO_GUARDFS" -eq 0 ]; then
    say "GuardFS 시작 (mount: $MOUNT_DIR)"
    PYTHONUNBUFFERED=1 bash "$PROJECT_ROOT/scripts/run_guardfs.sh" > "$GUARDFS_LOG" 2>&1 &
    GUARDFS_PID=$!

    for _ in $(seq 1 40); do
        mountpoint -q "$MOUNT_DIR" && break
        kill -0 "$GUARDFS_PID" 2>/dev/null || { tail -n 30 "$GUARDFS_LOG"; fail "GuardFS가 종료되었습니다"; }
        sleep 0.5
    done
    mountpoint -q "$MOUNT_DIR" || { tail -n 30 "$GUARDFS_LOG"; fail "GuardFS 마운트 실패 (20초 초과)"; }
    say "GuardFS 마운트 완료"
    AGENT_ARGS+=( --stdout-log "$GUARDFS_LOG" )
else
    say "--no-guardfs: GuardFS를 띄우지 않습니다"
fi

# ----------------------------------------
# 4. 에이전트
# ----------------------------------------
PYTHONUNBUFFERED=1 python dashboard/agent.py "${AGENT_ARGS[@]}" > "$AGENT_LOG" 2>&1 &
AGENT_PID=$!
sleep 1
kill -0 "$AGENT_PID" 2>/dev/null || { tail -n 20 "$AGENT_LOG"; fail "에이전트가 시작되지 않았습니다"; }

if [ "$DEMO" -eq 1 ]; then
    say "샘플 이벤트 전송 (--demo)"
    python dashboard/agent.py --demo --demo-delay 0.3 --server "http://127.0.0.1:$PORT" >/dev/null
fi

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
cat <<EOF

========================================================
 실행 중   (Ctrl+C = 전부 종료)
--------------------------------------------------------
 대시보드  : http://127.0.0.1:$PORT   ${IP:+(외부: http://$IP:$PORT)}
 로그      : $LOG_DIR/{server,guardfs_stdout,agent}.log
 테스트    : (다른 터미널에서)
   cd $PROJECT_ROOT && source venv/bin/activate
   # 보호 폴더 (GuardFS 마운트를 거침)
   python3 experiments/simulators/sim_highentropy.py $MOUNT_DIR/sim_target --keep
   # 보호 없는 폴더 (비교용) → 대시보드 '파일 상태' 탭에서 나란히 확인
   python3 experiments/simulators/sim_highentropy.py $UNPROTECTED_DIR/sim_target --keep
========================================================
 아래는 에이전트가 대시보드로 보낸 이벤트입니다.

EOF

# 에이전트 로그를 보여주며 대기. 하나라도 죽으면 알리고 종료한다.
tail -n +1 -f "$AGENT_LOG" &
TAIL_PID=$!
while true; do
    for name_pid in "server:$SERVER_PID" "agent:$AGENT_PID" ${GUARDFS_PID:+"guardfs:$GUARDFS_PID"}; do
        name="${name_pid%%:*}"; pid="${name_pid##*:}"
        if ! kill -0 "$pid" 2>/dev/null; then
            echo ""
            say "$name 프로세스가 종료되었습니다. 마지막 로그:"
            case "$name" in
                server)  tail -n 20 "$SERVER_LOG" ;;
                agent)   tail -n 20 "$AGENT_LOG" ;;
                guardfs) tail -n 30 "$GUARDFS_LOG" ;;
            esac
            shutdown_all
        fi
    done
    sleep 2
done
