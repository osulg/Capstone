#!/bin/bash

set -e

echo "========================================"
echo " GuardFS Setup"
echo "========================================"

# 프로젝트 루트
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# 가상환경 경로
VENV_DIR="$PROJECT_ROOT/venv"

# GuardFS 런타임 경로
RUNTIME_DIR="$HOME/guardfs_runtime"
MOUNT_DIR="$RUNTIME_DIR/mount"
UNDERLAY_DIR="$RUNTIME_DIR/underlay"
LOG_DIR="$RUNTIME_DIR/logs"
QUARANTINE_DIR="$RUNTIME_DIR/quarantine"

# 시스템 Python 대신 uv로 Python 3.12를 관리한다.
PYTHON_VERSION="3.12"

check_python() {
    "$1" -c 'import sys; raise SystemExit(sys.version_info[:2] != (3, 12))'
}

echo "[1/6] 시스템 패키지 및 uv 확인"

sudo apt update
sudo apt install -y \
    curl ca-certificates build-essential fuse3 libfuse3-dev pkg-config

if command -v uv >/dev/null 2>&1; then
    UV_BIN="$(command -v uv)"
elif [ -x "$HOME/.local/bin/uv" ]; then
    UV_BIN="$HOME/.local/bin/uv"
else
    # 다운로드 실패 시 설치 스크립트를 실행하지 않는다.
    UV_INSTALLER="$(mktemp)"
    trap 'rm -f -- "$UV_INSTALLER"' EXIT
    curl --fail --location --retry 3 \
        https://astral.sh/uv/install.sh --output "$UV_INSTALLER"
    env UV_INSTALL_DIR="$HOME/.local/bin" UV_NO_MODIFY_PATH=1 sh "$UV_INSTALLER"
    rm -f -- "$UV_INSTALLER"
    trap - EXIT
    UV_BIN="$HOME/.local/bin/uv"
fi

"$UV_BIN" --version
"$UV_BIN" python install "$PYTHON_VERSION"

echo "[2/6] Python 가상환경 생성"

# 기존 환경을 활성화한 터미널에서 실행해도 해당 환경을 사용하지 않는다.
unset VIRTUAL_ENV

if [ -e "$VENV_DIR" ] || [ -L "$VENV_DIR" ]; then
    if [ -f "$VENV_DIR/bin/activate" ] && \
        [ -x "$VENV_DIR/bin/python" ] && \
        check_python "$VENV_DIR/bin/python"; then
        echo "기존 Python 3.12 가상환경을 재사용합니다."
    else
        VENV_BACKUP="$VENV_DIR.backup-$(date +%Y%m%d-%H%M%S)-$$"
        mv -- "$VENV_DIR" "$VENV_BACKUP"
        echo "기존 가상환경 백업: $VENV_BACKUP"
    fi
fi

if [ ! -d "$VENV_DIR" ]; then
    "$UV_BIN" venv --python "$PYTHON_VERSION" "$VENV_DIR"
fi

if ! check_python "$VENV_DIR/bin/python"; then
    echo "[ERROR] Python 3.12 가상환경을 생성하지 못했습니다."
    exit 1
fi
echo "사용할 Python: $VENV_DIR/bin/python ($("$VENV_DIR/bin/python" --version))"

echo "[3/6] Python 패키지 설치"

if [ -f "$PROJECT_ROOT/requirements.txt" ]; then
    "$UV_BIN" pip install --python "$VENV_DIR/bin/python" \
        -r "$PROJECT_ROOT/requirements.txt"
else
    echo "requirements.txt가 없어 기본 패키지만 설치합니다."
    "$UV_BIN" pip install --python "$VENV_DIR/bin/python" \
        pyfuse3 trio numpy pandas scikit-learn psutil
fi

"$UV_BIN" pip check --python "$VENV_DIR/bin/python"

echo "[4/6] GuardFS 런타임 디렉터리 생성"

mkdir -p "$MOUNT_DIR"
mkdir -p "$UNDERLAY_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$QUARANTINE_DIR"

echo "Mount      : $MOUNT_DIR"
echo "Underlay   : $UNDERLAY_DIR"
echo "Logs       : $LOG_DIR"
echo "Quarantine : $QUARANTINE_DIR"

echo "[5/6] 스크립트 실행 권한 설정"

chmod +x "$PROJECT_ROOT"/scripts/*.sh

echo "[6/6] Setup 완료"

echo ""
echo "========================================"
echo " GuardFS 환경 준비 완료"
echo "========================================"
echo ""
echo "가상환경 활성화:"
echo "  source $VENV_DIR/bin/activate"
echo ""
echo "GuardFS 실행:"
echo "  ./scripts/run_guardfs.sh"
echo ""
