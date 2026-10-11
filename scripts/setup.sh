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

# 기본 Python 버전 (시스템 python3는 변경하지 않음)
PYTHON_BIN="python3.12"
PYTHON_SOURCE_VERSION="3.12.15"
PYTHON_SOURCE_SHA256="de1a241a519e0a3374fea98988d0b52c886743f9d953f23be8269cc7b59c5fab"
PYTHON_INSTALL_DIR="$HOME/.local/guardfs/python-$PYTHON_SOURCE_VERSION"

check_python() {
    "$1" -c '
import sys
import ensurepip
import ssl
import venv
import sysconfig
from pathlib import Path
if sys.version_info < (3, 12):
    raise SystemExit("Python 3.12 이상이 필요합니다.")
if not (Path(sysconfig.get_path("include")) / "Python.h").is_file():
    raise SystemExit("Python 개발 헤더(Python.h)가 없습니다.")
'
}

install_python_from_source() (
    # subshell의 임시 빌드 디렉터리만 정리하며 기존 설치는 보존한다.
    local build_dir
    build_dir="$(mktemp -d)"
    trap 'rm -rf -- "$build_dir"' EXIT

    sudo apt install -y \
        curl ca-certificates libssl-dev zlib1g-dev libbz2-dev \
        libreadline-dev libsqlite3-dev libffi-dev liblzma-dev \
        libncursesw5-dev uuid-dev

    echo "Python $PYTHON_SOURCE_VERSION 소스를 빌드합니다. 몇 분 걸릴 수 있습니다."
    cd "$build_dir"
    curl --fail --location --retry 3 \
        "https://www.python.org/ftp/python/$PYTHON_SOURCE_VERSION/Python-$PYTHON_SOURCE_VERSION.tgz" \
        --output python.tgz
    printf '%s  python.tgz\n' "$PYTHON_SOURCE_SHA256" | sha256sum --check -
    tar -xzf python.tgz
    cd "Python-$PYTHON_SOURCE_VERSION"
    ./configure --prefix="$PYTHON_INSTALL_DIR" --with-ensurepip=install
    # VM의 메모리 사용량을 제한한다.
    make -j2
    make altinstall
)

echo "[1/6] 시스템 패키지 확인"

sudo apt update
sudo apt install -y \
    build-essential \
    fuse3 \
    libfuse3-dev \
    pkg-config

# PATH에 없는 사용자 설치 및 이전 setup에서 생성한 설치도 탐색한다.
if command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v "$PYTHON_BIN")"
elif [ -x "$HOME/.local/bin/python3.12" ]; then
    PYTHON_BIN="$HOME/.local/bin/python3.12"
elif [ -x "$PYTHON_INSTALL_DIR/bin/python3.12" ]; then
    PYTHON_BIN="$PYTHON_INSTALL_DIR/bin/python3.12"
else
    . /etc/os-release
    if [ "$ID" = "ubuntu" ] && [ "$VERSION_ID" = "22.04" ]; then
        sudo apt install -y software-properties-common
        sudo add-apt-repository -y ppa:deadsnakes/ppa
        sudo apt update
    fi

    if apt-cache show python3.12 >/dev/null 2>&1; then
        sudo apt install -y python3.12 python3.12-venv python3.12-dev
        PYTHON_BIN="$(command -v python3.12)"
    else
        # Ubuntu 20.04 등 APT에 패키지가 없는 환경의 신규 설치.
        install_python_from_source
        PYTHON_BIN="$PYTHON_INSTALL_DIR/bin/python3.12"
    fi
fi

if ! check_python "$PYTHON_BIN"; then
    echo "[ERROR] $PYTHON_BIN 의 버전, venv/ensurepip/SSL 또는 개발 헤더를 확인하세요."
    exit 1
fi
echo "사용할 Python: $PYTHON_BIN ($("$PYTHON_BIN" --version))"

echo "[2/6] Python 가상환경 생성"

if [ ! -d "$VENV_DIR" ]; then
    "$PYTHON_BIN" -m venv "$VENV_DIR"
    echo "가상환경 생성 완료: $VENV_DIR ($("$PYTHON_BIN" --version))"
else
    if [ ! -f "$VENV_DIR/bin/activate" ] || \
        [ ! -x "$VENV_DIR/bin/python" ] || \
        ! check_python "$VENV_DIR/bin/python"; then
        echo "[ERROR] 기존 venv가 불완전하거나 Python 3.12 이상 환경이 아닙니다."
        echo "기존 venv를 다른 이름으로 옮긴 뒤 setup.sh를 다시 실행하세요."
        exit 1
    fi
    echo "기존 가상환경 재사용: $("$VENV_DIR/bin/python" --version)"
fi

echo "[3/6] Python 패키지 설치"

source "$VENV_DIR/bin/activate"

python -m pip install --upgrade pip

if [ -f "$PROJECT_ROOT/requirements.txt" ]; then
    python -m pip install -r "$PROJECT_ROOT/requirements.txt"
else
    echo "requirements.txt가 없어 기본 패키지만 설치합니다."

    python -m pip install \
        pyfuse3 \
        trio \
        numpy \
        pandas \
        scikit-learn \
        psutil
fi

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
