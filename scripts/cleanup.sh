#!/bin/bash

set -e

echo "========================================"
echo " GuardFS Cleanup"
echo "========================================"

# ----------------------------------------
# 1. 런타임 경로
# ----------------------------------------
RUNTIME_DIR="$HOME/guardfs_runtime"
MOUNT_DIR="$RUNTIME_DIR/mount"
UNDERLAY_DIR="$RUNTIME_DIR/underlay"
LOG_DIR="$RUNTIME_DIR/logs"

echo "[INFO] Runtime  : $RUNTIME_DIR"
echo "[INFO] Mount    : $MOUNT_DIR"
echo "[INFO] Underlay : $UNDERLAY_DIR"
echo "[INFO] Logs     : $LOG_DIR"
echo ""

# ----------------------------------------
# 2. GuardFS가 아직 마운트되어 있는지 확인
# ----------------------------------------
if mountpoint -q "$MOUNT_DIR" 2>/dev/null; then
    echo "[ERROR] GuardFS가 아직 마운트되어 있습니다."
    echo "먼저 다음 명령을 실행하세요:"
    echo ""
    echo "  ./scripts/unmount.sh"
    echo ""
    exit 1
fi

# ----------------------------------------
# 3. mount 디렉터리 내부 정리
# ----------------------------------------
if [ -d "$MOUNT_DIR" ]; then
    echo "[INFO] Cleaning mount directory..."
    find "$MOUNT_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
    echo "[OK] Mount directory cleaned"
fi

# ----------------------------------------
# 4. 로그 정리
# ----------------------------------------
if [ -d "$LOG_DIR" ]; then
    echo "[INFO] Cleaning logs..."
    find "$LOG_DIR" -type f -delete
    echo "[OK] Logs cleaned"
fi

# ----------------------------------------
# 5. GuardFS 임시 상태 파일 정리
# ----------------------------------------
echo "[INFO] Cleaning temporary GuardFS files..."

rm -f /tmp/guardfs_stage2_*.json
rm -f /tmp/guardfs_*.tmp
rm -f /tmp/guardfs_*.pid

echo "[OK] Temporary files cleaned"

# ----------------------------------------
# 6. 완료
# ----------------------------------------
echo ""
echo "========================================"
echo " GuardFS Cleanup Complete"
echo "========================================"
echo ""
echo "[INFO] Underlay data was NOT deleted."
echo "       $UNDERLAY_DIR"