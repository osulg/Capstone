#!/bin/bash

set -e

echo "========================================"
echo " GuardFS Unmount"
echo "========================================"

# ----------------------------------------
# 1. GuardFS 런타임 경로
# ----------------------------------------
RUNTIME_DIR="$HOME/guardfs_runtime"
MOUNT_DIR="$RUNTIME_DIR/mount"

echo "[INFO] Mount : $MOUNT_DIR"
echo ""

# ----------------------------------------
# 2. 마운트 디렉터리 존재 여부 확인
# ----------------------------------------
if [ ! -d "$MOUNT_DIR" ]; then
    echo "[INFO] 마운트 디렉터리가 존재하지 않습니다."
    echo "Nothing to unmount."
    exit 0
fi

# ----------------------------------------
# 3. 실제 마운트 여부 확인
# ----------------------------------------
if ! mountpoint -q "$MOUNT_DIR"; then
    echo "[INFO] GuardFS가 현재 마운트되어 있지 않습니다."
    echo "Nothing to unmount."
    exit 0
fi

# ----------------------------------------
# 4. FUSE 마운트 해제
# ----------------------------------------
echo "[INFO] Unmounting GuardFS..."

if command -v fusermount3 >/dev/null 2>&1; then
    fusermount3 -u "$MOUNT_DIR"
elif command -v fusermount >/dev/null 2>&1; then
    fusermount -u "$MOUNT_DIR"
else
    echo "[ERROR] fusermount 명령을 찾을 수 없습니다."
    exit 1
fi

# ----------------------------------------
# 5. 마운트 해제 결과 확인
# ----------------------------------------
if mountpoint -q "$MOUNT_DIR"; then
    echo "[ERROR] GuardFS 마운트 해제에 실패했습니다."
    exit 1
fi

echo ""
echo "========================================"
echo " GuardFS Unmounted Successfully"
echo "========================================"