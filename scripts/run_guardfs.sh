#!/bin/bash

set -e

echo "========================================"
echo " GuardFS Start"
echo "========================================"

# ----------------------------------------
# 1. 프로젝트 루트 경로
# ----------------------------------------

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# ----------------------------------------
# 2. 가상환경 경로
# ----------------------------------------

VENV_DIR="$PROJECT_ROOT/venv"

# ----------------------------------------
# 3. GuardFS 런타임 경로
# ----------------------------------------

RUNTIME_DIR="$HOME/guardfs_runtime"
MOUNT_DIR="$RUNTIME_DIR/mount"
UNDERLAY_DIR="$RUNTIME_DIR/underlay"

echo "[INFO] Project  : $PROJECT_ROOT"
echo "[INFO] Mount    : $MOUNT_DIR"
echo "[INFO] Underlay : $UNDERLAY_DIR"
echo ""

# ----------------------------------------
# 4. 가상환경 확인
# ----------------------------------------

if [ ! -d "$VENV_DIR" ]; then
    echo "[ERROR] Python 가상환경이 없습니다."
    echo "먼저 다음 명령을 실행하세요:"
    echo ""
    echo "  ./scripts/setup.sh"
    echo ""
    exit 1
fi

# ----------------------------------------
# 5. 가상환경 활성화
# ----------------------------------------

source "$VENV_DIR/bin/activate"

echo "[OK] Python virtual environment activated"

# ----------------------------------------
# 6. 런타임 디렉터리 확인
# ----------------------------------------

mkdir -p "$MOUNT_DIR"
mkdir -p "$UNDERLAY_DIR"

echo "[OK] Runtime directories ready"

# ----------------------------------------
# 7. 이미 마운트되어 있는지 확인
# ----------------------------------------

if mountpoint -q "$MOUNT_DIR"; then
    echo ""
    echo "[ERROR] GuardFS가 이미 마운트되어 있습니다."
    echo "Mount point: $MOUNT_DIR"
    echo ""
    echo "먼저 다음 명령으로 언마운트하세요:"
    echo ""
    echo "  ./scripts/unmount.sh"
    echo ""
    exit 1
fi

# ----------------------------------------
# 8. 프로젝트 루트로 이동
# ----------------------------------------

cd "$PROJECT_ROOT"

# ----------------------------------------
# 9. GuardFS 실행
# ----------------------------------------

echo ""
echo "========================================"
echo " Starting GuardFS"
echo "========================================"
echo ""

python3 guardfs/fuse_fs/passthrough.py \
    "$MOUNT_DIR" \
    "$UNDERLAY_DIR"