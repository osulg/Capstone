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

echo "[1/6] 시스템 패키지 확인"

sudo apt update

sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    fuse3 \
    libfuse3-dev \
    pkg-config

echo "[2/6] Python 가상환경 생성"

if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    echo "가상환경 생성 완료: $VENV_DIR"
else
    echo "가상환경이 이미 존재합니다."
fi

echo "[3/6] Python 패키지 설치"

source "$VENV_DIR/bin/activate"

python -m pip install --upgrade pip

if [ -f "$PROJECT_ROOT/requirements.txt" ]; then
    pip install -r "$PROJECT_ROOT/requirements.txt"
else
    echo "requirements.txt가 없어 기본 패키지만 설치합니다."

    pip install \
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