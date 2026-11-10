#!/usr/bin/env bash
# Ubuntu 데스크톱에서 HoldFS/대시보드, API, React 터미널을 순서대로 연다.
# 설치는 하지 않으며, 준비 확인을 통과해야 다음 서비스를 시작한다.
set -euo pipefail

SCRIPT_PATH="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/$(basename -- "${BASH_SOURCE[0]}")"
PROJECT_ROOT="$(cd -- "$(dirname -- "$SCRIPT_PATH")/.." && pwd)"
BACKEND_PYTHON="$PROJECT_ROOT/demo-web/backend/.venv/bin/python"
MOUNT_DIR="$HOME/guardfs_runtime/mount"

fail() { printf '[HoldFS Demo] 오류: %s\n' "$*" >&2; exit 1; }

load_node() {
    # GNOME Terminal의 데몬이 이전 PATH를 사용하더라도 nvm을 직접 불러온다.
    local node_nvm_dir="${NVM_DIR:-$HOME/.nvm}"
    if [ -s "$node_nvm_dir/nvm.sh" ]; then
        export NVM_DIR="$node_nvm_dir"
        source "$NVM_DIR/nvm.sh" --no-use
        nvm use 24 --silent || fail '설치된 Node.js 24가 필요합니다. nvm install 24를 먼저 실행하세요.'
    fi
    command -v node >/dev/null || fail 'Node.js가 없습니다.'
    command -v npm >/dev/null || fail 'npm이 없습니다.'
    node -e '
      const [major, minor] = process.versions.node.split(".").map(Number);
      process.exit((major === 20 && minor >= 19) ||
        (major === 22 && minor >= 12) || major >= 24 ? 0 : 1);
    ' || fail 'Node.js 버전이 낮습니다. Node.js 24를 사용하세요.'
}

if [ "${1:-}" = '--help' ] || [ "${1:-}" = '-h' ]; then
    printf '사용법: bash scripts/run_demo_web.sh\nUbuntu GNOME 데스크톱에서 준비된 서비스를 터미널 3개로 실행합니다.\nHoldFS 창에서 AI 분석관 LLM 제공자와 API 키를 입력합니다. 묻지 않고 로컬 모드로 띄우려면 HOLDFS_DEMO_LLM=local.\n'
    exit 0
fi

[ "$(uname -s)" = Linux ] || fail 'VMware Ubuntu 내부에서 실행하세요.'
cd "$PROJECT_ROOT"

# 새 터미널이 실행할 내부 진입점. 외부 명령 문자열을 eval하지 않는다.
if [ "${1:-}" = '--service' ]; then
    # 종료 후에도 오류를 읽을 수 있도록 터미널을 유지한다.
    trap 'service_rc=$?; printf "\n서비스 종료 (코드 %s).\n" "$service_rc"; read -r -p "Enter를 누르면 창을 닫습니다." _ || true; exit "$service_rc"' EXIT
    case "${2:-}" in
        holdfs)
            # 기존 실행기를 재사용한다. 기본은 이 창에서 AI 분석관의 LLM 제공자와 API 키를
            # 직접 입력받는다(run_all.sh 가 키를 화면에 표시하지 않고 대시보드 서버에만 넘기며
            # 파일·셸 기록에 남기지 않는다). HOLDFS_DEMO_LLM=local 이면 묻지 않고 로컬 모드.
            if [ "${HOLDFS_DEMO_LLM:-ask}" = local ]; then
                printf '4\n' | DASH_HOST=127.0.0.1 DASH_PORT=5000 \
                    bash "$PROJECT_ROOT/dashboard/run_all.sh"
            else
                DASH_HOST=127.0.0.1 DASH_PORT=5000 \
                    bash "$PROJECT_ROOT/dashboard/run_all.sh"
            fi
            ;;
        api)
            export PYTHONPATH="$PROJECT_ROOT:$PROJECT_ROOT/demo-web/backend${PYTHONPATH:+:$PYTHONPATH}"
            "$BACKEND_PYTHON" -m uvicorn app.main:app \
                --host 127.0.0.1 --port 8000 --workers 1
            ;;
        frontend)
            load_node
            cd "$PROJECT_ROOT/demo-web/frontend"
            npm run dev -- --host 127.0.0.1 --port 5173 --strictPort
            ;;
        *) fail '알 수 없는 서비스입니다.' ;;
    esac
    exit 0
fi

[ "$#" -eq 0 ] || fail '지원하지 않는 인자입니다. --help를 확인하세요.'
for required_command in gnome-terminal curl mountpoint pgrep flock; do
    command -v "$required_command" >/dev/null || fail "$required_command 명령이 없습니다. 자동 설치는 하지 않습니다."
done
[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] || fail 'Ubuntu 데스크톱 터미널에서 실행하세요. GUI 없는 SSH 세션은 지원하지 않습니다.'

# 두 실행기가 동시에 새 서버를 띄우지 않도록 시작 과정에 잠금을 건다.
exec 9>"${XDG_RUNTIME_DIR:-/tmp}/holdfs-demo-launch-${UID}.lock"
flock -n 9 || fail '다른 실행기가 준비 중입니다.'

[ -x "$PROJECT_ROOT/venv/bin/python" ] || fail 'HoldFS venv가 없습니다. scripts/setup.sh로 먼저 준비하세요.'
[ -x "$BACKEND_PYTHON" ] || fail '웹 백엔드 .venv를 먼저 준비하세요.'
[ -f "$PROJECT_ROOT/demo-web/frontend/node_modules/vite/bin/vite.js" ] || fail '프런트 의존성이 없습니다. frontend 폴더에서 npm ci를 먼저 실행하세요.'
[ -f "$PROJECT_ROOT/dashboard/web/dist/index.html" ] || fail '대시보드 화면 빌드가 없습니다. bash scripts/setup_demo_web.sh를 먼저 실행하세요.'
load_node

"$PROJECT_ROOT/venv/bin/python" -c 'import pyfuse3, trio, flask' || fail 'HoldFS/대시보드 의존성을 확인하세요.'
"$BACKEND_PYTHON" -c 'import fastapi, uvicorn, pydantic; assert int(pydantic.__version__.split(".")[0]) == 2' || fail 'FastAPI 의존성을 확인하세요.'
PYTHONPATH="$PROJECT_ROOT:$PROJECT_ROOT/demo-web/backend${PYTHONPATH:+:$PYTHONPATH}" \
    "$BACKEND_PYTHON" -c 'import app.main' || fail 'API 코드 import에 실패했습니다.'

# 기존 서버를 자동으로 종료하거나 재사용하지 않는다.
if mountpoint -q "$MOUNT_DIR"; then
    fail 'HoldFS가 이미 마운트되어 있습니다. 기존 테스트를 완료하고 서비스를 종료한 뒤 실행하세요.'
fi
if pgrep -f '[d]ashboard/(agent|server)\.py|[g]uardfs/fuse_fs/passthrough\.py' >/dev/null; then
    fail '기존 HoldFS/대시보드 프로세스가 있습니다. 기존 실행 상태를 먼저 확인하세요.'
fi
"$BACKEND_PYTHON" - <<'PY'
import socket
for port in (5000, 8000, 5173):
    with socket.socket() as server:
        # 종료된 서버의 TIME_WAIT 연결만으로 빈 포트를 사용 중으로
        # 오판하지 않는다. 실제 LISTEN 중인 서버의 포트는 계속 거부한다.
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("127.0.0.1", port))
        except OSError as error:
            raise SystemExit(
                f"포트 {port}를 사용할 수 없습니다: {error}\n"
                f"사용 중인 서버 확인: ss -ltnp 'sport = :{port}'\n"
                "이전 서비스 터미널에서 Ctrl+C로 종료한 뒤 다시 실행하세요."
            )
PY

open_terminal() {
    gnome-terminal --wait --window --title="$1" \
        -- bash "$SCRIPT_PATH" --service "$2" 9>&- &
    TERMINAL_PID=$!
}

wait_ready() {
    local label="$1" url="$2" require_mount="${3:-no}" limit="${4:-90}"
    local deadline=$((SECONDS + limit))
    printf '[HoldFS Demo] %s 준비 확인 중…\n' "$label"
    while (( SECONDS < deadline )); do
        if ! kill -0 "$TERMINAL_PID" 2>/dev/null; then
            fail "$label 터미널이 종료됐습니다. 해당 창의 오류를 확인하세요."
        fi
        if curl --noproxy '*' -fsS --connect-timeout 1 --max-time 2 \
            "$url" >/dev/null 2>&1; then
            if [ "$require_mount" != yes ] || mountpoint -q "$MOUNT_DIR"; then
                printf '[HoldFS Demo] %s 준비 완료\n' "$label"
                return 0
            fi
        fi
        sleep 1
    done
    fail "$label 준비가 ${limit}초 내 확인되지 않았습니다. 열린 창을 확인하세요. 이미 열린 서비스는 자동 종료하지 않습니다."
}

open_terminal 'HoldFS · Dashboard' holdfs
if [ "${HOLDFS_DEMO_LLM:-ask}" = local ]; then
    wait_ready 'HoldFS / 대시보드' 'http://127.0.0.1:5000/api/health' yes
else
    printf '[HoldFS Demo] 새로 열린 "HoldFS · Dashboard" 창에서 AI 분석관 LLM 제공자와 API 키를 입력하세요.\n'
    printf '[HoldFS Demo] (키 없이 쓰려면 4번 또는 키 입력에서 Enter = 로컬 모드)\n'
    # 사람이 입력하는 시간을 포함해 넉넉히 기다린다.
    wait_ready 'HoldFS / 대시보드' 'http://127.0.0.1:5000/api/health' yes 300
fi
# API만 살아 있고 화면 빌드가 없으면 대시보드 첫 화면이 503이 된다.
curl --noproxy '*' -fsS --connect-timeout 1 --max-time 3 \
    'http://127.0.0.1:5000/' >/dev/null 2>&1 \
    || fail '대시보드 화면을 불러오지 못했습니다. dashboard/web/dist 빌드를 확인하세요. 이미 열린 서비스는 자동 종료하지 않습니다.'
open_terminal 'HoldFS · FastAPI' api
wait_ready 'FastAPI' 'http://127.0.0.1:8000/api/scenarios'
open_terminal 'HoldFS · React' frontend
wait_ready 'React / API 프록시' 'http://127.0.0.1:5173/api/scenarios'

cat <<'INFO'

HoldFS 웹 시연 환경 준비 완료
  React       http://127.0.0.1:5173
  API 문서    http://127.0.0.1:8000/docs
  대시보드    http://127.0.0.1:5000

VM 내부 브라우저에서 React 주소를 여세요. 테스트는 자동 실행하지 않습니다.
종료: 테스트 완료 후 React → FastAPI → HoldFS/대시보드 창에서 각각 Ctrl+C.
이 실행기를 종료해도 열린 서비스는 계속 실행됩니다.
INFO
