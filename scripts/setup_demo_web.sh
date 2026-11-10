#!/usr/bin/env bash
# Ubuntu 웹 시연 환경의 설치·확인 도구. 인자가 없으면 설치만 수행한다.
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
HOLDFS_PYTHON="$PROJECT_ROOT/venv/bin/python"
BACKEND_ENV="$PROJECT_ROOT/demo-web/backend/.venv"
BACKEND_PYTHON="$BACKEND_ENV/bin/python"
FRONTEND_DIR="$PROJECT_ROOT/demo-web/frontend"
DASHBOARD_WEB_DIR="$PROJECT_ROOT/dashboard/web"
NODE_NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
NVM_VERSION="v0.40.8"
INSTALLER_FILE=""

fail() { printf '[HoldFS Demo] 오류: %s\n' "$*" >&2; exit 1; }
say() { printf '[HoldFS Demo] %s\n' "$*"; }

usage() {
    cat <<'HELP'
사용법: bash scripts/setup_demo_web.sh [setup|check|run]

  setup  최초 설치. 기존 환경은 재사용하고 변경된 의존성만 설치합니다. 기본 동작입니다.
  check  Python 환경·API import·프런트 빌드·대시보드 화면 빌드를 확인합니다.
  run    준비된 HoldFS·대시보드·API·React를 실행합니다.

최초 한 번: bash scripts/setup_demo_web.sh
평소 실행: bash scripts/run_demo_web.sh
코드 반영 후 확인: bash scripts/setup_demo_web.sh check

Ubuntu 데스크톱에서 일반 사용자로 실행하세요. setup 중 sudo 비밀번호를
요청할 수 있습니다. 서비스 종료는 열린 각 터미널에서 Ctrl+C로 진행합니다.
HELP
}

cleanup_installer() {
    if [ -n "$INSTALLER_FILE" ]; then
        rm -f -- "$INSTALLER_FILE"
    fi
}
trap cleanup_installer EXIT

find_uv() {
    if command -v uv >/dev/null 2>&1; then
        UV_BIN="$(command -v uv)"
    elif [ -x "$HOME/.local/bin/uv" ]; then
        UV_BIN="$HOME/.local/bin/uv"
    else
        fail 'uv가 없습니다. setup을 먼저 실행하세요.'
    fi
}

valid_python() {
    [ -x "$1" ] && "$1" -c \
        'import sys; raise SystemExit(sys.version_info[:2] != (3, 12))'
}

load_nvm() {
    export NVM_DIR="$NODE_NVM_DIR"
    # 외부 nvm 스크립트의 선택적 변수가 nounset에 걸리지 않도록 한다.
    set +u
    source "$NVM_DIR/nvm.sh" --no-use
    set -u
}

load_node() {
    if [ -s "$NODE_NVM_DIR/nvm.sh" ]; then
        load_nvm
        nvm use 24 --silent || fail 'Node.js 24가 없습니다. setup을 실행하세요.'
    fi
    command -v node >/dev/null || fail 'Node.js가 없습니다. setup을 실행하세요.'
    command -v npm >/dev/null || fail 'npm이 없습니다. setup을 실행하세요.'
    node -e 'process.exit(Number(process.versions.node.split(".")[0]) === 24 ? 0 : 1)' \
        || fail 'Node.js 24가 필요합니다. setup을 실행하세요.'
}

setup_node() {
    if [ ! -s "$NODE_NVM_DIR/nvm.sh" ]; then
        if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1 &&
            node -e 'process.exit(Number(process.versions.node.split(".")[0]) === 24 ? 0 : 1)'; then
            say '기존 Node.js 24와 npm을 재사용합니다.'
            return
        fi

        # 다운로드가 완료된 파일만 실행하고 셸 프로필은 변경하지 않는다.
        INSTALLER_FILE="$(mktemp)"
        curl --fail --location --retry 3 \
            "https://raw.githubusercontent.com/nvm-sh/nvm/$NVM_VERSION/install.sh" \
            --output "$INSTALLER_FILE"
        env PROFILE=/dev/null METHOD=script NVM_DIR="$NODE_NVM_DIR" \
            bash "$INSTALLER_FILE"
        cleanup_installer
        INSTALLER_FILE=""
    fi

    load_nvm
    if [ "$(nvm version 24)" = 'N/A' ]; then
        nvm install 24
    fi
    nvm alias default 24
    nvm use 24 --silent
}

# 대시보드(5000)는 Flask가 커밋된 dashboard/web/dist를 그대로 서빙한다.
# 빌드 결과가 없거나 index.html이 가리키는 파일이 빠졌으면 화면이 비어 보인다.
dashboard_web_ready() {
    local index="$DASHBOARD_WEB_DIR/dist/index.html" asset
    [ -f "$index" ] || return 1
    while IFS= read -r asset; do
        [ -f "$DASHBOARD_WEB_DIR/dist/$asset" ] || return 1
    done < <(grep -oE '/assets/[^"]+' "$index" | sed 's#^/##')
}

# 빌드 결과가 온전하면 다시 빌드하지 않는다(커밋된 dist를 바꾸지 않기 위해).
prepare_dashboard_web() {
    if dashboard_web_ready; then
        say '기존 대시보드 화면 빌드를 재사용합니다.'
        return 0
    fi
    say '대시보드 화면 빌드가 없어 dashboard/web에서 빌드합니다.'
    (cd "$DASHBOARD_WEB_DIR" && npm ci && npm run build)
    dashboard_web_ready || fail '대시보드 화면 빌드에 실패했습니다.'
}

check_environment() {
    valid_python "$HOLDFS_PYTHON" || fail 'HoldFS Python 3.12 환경이 없습니다. setup을 실행하세요.'
    valid_python "$BACKEND_PYTHON" || fail 'API Python 3.12 환경이 없습니다. setup을 실행하세요.'
    "$HOLDFS_PYTHON" -c 'import pyfuse3, trio, flask' \
        || fail 'HoldFS 의존성을 확인하세요. setup을 실행하세요.'
    "$BACKEND_PYTHON" -c \
        'import fastapi, uvicorn, pydantic; assert int(pydantic.__version__.split(".")[0]) == 2' \
        || fail 'API 의존성 또는 Pydantic 2.x를 확인하세요. setup을 실행하세요.'
    PYTHONPATH="$PROJECT_ROOT:$PROJECT_ROOT/demo-web/backend${PYTHONPATH:+:$PYTHONPATH}" \
        "$BACKEND_PYTHON" -c 'from app.main import app; print("API import 성공")'
    load_node
    [ -f "$FRONTEND_DIR/node_modules/vite/bin/vite.js" ] \
        || fail '프런트 의존성이 없습니다. setup을 실행하세요.'
    dashboard_web_ready \
        || fail '대시보드 화면 빌드(dashboard/web/dist)가 없거나 불완전합니다. setup을 실행하세요.'
}

setup_environment() {
    say '1/4 HoldFS 환경 준비'
    if ! valid_python "$HOLDFS_PYTHON" ||
        ! "$HOLDFS_PYTHON" -c 'import pyfuse3, trio, flask' >/dev/null 2>&1 ||
        { ! command -v uv >/dev/null 2>&1 && [ ! -x "$HOME/.local/bin/uv" ]; }; then
        bash "$PROJECT_ROOT/scripts/setup.sh"
    else
        say '기존 HoldFS 환경을 재사용합니다.'
    fi
    find_uv

    # 데스크톱 실행기에 필요한 명령이 없을 때만 시스템 패키지를 설치한다.
    local packages=()
    command -v curl >/dev/null || packages+=(curl ca-certificates)
    command -v gnome-terminal >/dev/null || packages+=(gnome-terminal)
    command -v pgrep >/dev/null || packages+=(procps)
    if ! command -v flock >/dev/null || ! command -v mountpoint >/dev/null; then
        packages+=(util-linux)
    fi
    if [ "${#packages[@]}" -gt 0 ]; then
        sudo apt update
        sudo apt install -y "${packages[@]}"
    fi

    say '2/4 FastAPI 전용 환경 준비'
    if [ -e "$BACKEND_ENV" ] || [ -L "$BACKEND_ENV" ]; then
        valid_python "$BACKEND_PYTHON" \
            || fail '기존 backend/.venv가 Python 3.12 환경이 아닙니다. 덮어쓰지 않고 중단합니다.'
    else
        "$UV_BIN" venv --python 3.12 --seed "$BACKEND_ENV"
    fi

    local backend_requirements="$PROJECT_ROOT/demo-web/backend/requirements.txt"
    local backend_stamp="$BACKEND_ENV/.holdfs-demo-requirements"
    local backend_fingerprint
    backend_fingerprint="$(sha256sum "$backend_requirements")"
    if [ ! -f "$backend_stamp" ] ||
        [ "$(cat "$backend_stamp")" != "$backend_fingerprint" ] ||
        ! "$BACKEND_PYTHON" -c 'import fastapi, uvicorn, pydantic; assert int(pydantic.__version__.split(".")[0]) == 2' >/dev/null 2>&1; then
        "$UV_BIN" pip install --python "$BACKEND_PYTHON" -r "$backend_requirements"
        "$UV_BIN" pip check --python "$BACKEND_PYTHON"
        printf '%s\n' "$backend_fingerprint" > "$backend_stamp"
    else
        say '기존 FastAPI 의존성을 재사용합니다.'
    fi

    say '3/4 Node.js 24와 프런트 의존성 준비'
    setup_node
    cd "$FRONTEND_DIR"
    local frontend_stamp="$FRONTEND_DIR/node_modules/.holdfs-demo-inputs"
    local frontend_fingerprint
    frontend_fingerprint="$(sha256sum package.json package-lock.json)
$(node --version)
$(npm --version)"
    if [ ! -f "$frontend_stamp" ] ||
        [ "$(cat "$frontend_stamp")" != "$frontend_fingerprint" ] ||
        [ ! -f node_modules/vite/bin/vite.js ] ||
        [ ! -f node_modules/typescript/bin/tsc ]; then
        npm ci
        printf '%s\n' "$frontend_fingerprint" > "$frontend_stamp"
    else
        say '기존 프런트 의존성을 재사용합니다.'
    fi
    prepare_dashboard_web

    say '4/4 API import와 프런트 빌드 확인'
    cd "$PROJECT_ROOT"
    check_environment
    # build에 TypeScript 검사가 포함되어 있으므로 중복 실행하지 않는다.
    (cd "$FRONTEND_DIR" && npm run build)
    say '설치 완료. 서비스 실행: bash scripts/run_demo_web.sh'
}

case "${1:-setup}" in
    -h|--help|help) usage; exit 0 ;;
    setup|check|run) action="${1:-setup}" ;;
    *) usage; exit 1 ;;
esac
[ "$#" -le 1 ] || fail '인자는 setup, check, run 중 하나만 지정하세요.'
[ "$(uname -s)" = Linux ] || fail 'VMware Ubuntu 내부에서 실행하세요.'
[ "$EUID" -ne 0 ] || fail 'sudo bash가 아닌 일반 사용자로 실행하세요.'
cd "$PROJECT_ROOT"

case "$action" in
    setup) setup_environment ;;
    check)
        check_environment
        (cd "$FRONTEND_DIR" && npm run build)
        say '환경과 빌드 확인 완료'
        ;;
    run)
        # 실제 서비스 시작·포트 확인·기존 프로세스 보호는 기존 실행기에 맡긴다.
        exec bash "$PROJECT_ROOT/scripts/run_demo_web.sh"
        ;;
esac
