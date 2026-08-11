#!/bin/bash

set -e

echo "========================================"
echo " GuardFS Simple Test"
echo "========================================"

# ----------------------------------------
# 1. 프로젝트 경로
# ----------------------------------------

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

VENV_DIR="$PROJECT_ROOT/venv"

RUNTIME_DIR="$HOME/guardfs_runtime"
MOUNT_DIR="$RUNTIME_DIR/mount"
UNDERLAY_DIR="$RUNTIME_DIR/underlay"


# ----------------------------------------
# 2. 가상환경 활성화
# ----------------------------------------

if [ ! -d "$VENV_DIR" ]; then
    echo "[ERROR] venv가 없습니다."
    echo "먼저 실행하세요:"
    echo "  ./scripts/setup.sh"
    exit 1
fi

source "$VENV_DIR/bin/activate"

echo "[OK] Virtual environment activated"


# ----------------------------------------
# 3. GuardFS 마운트 확인
# ----------------------------------------

if ! mountpoint -q "$MOUNT_DIR"; then
    echo "[ERROR] GuardFS가 실행 중이 아닙니다."
    echo "먼저 실행하세요:"
    echo "  ./scripts/run_guardfs.sh"
    exit 1
fi

echo "[OK] GuardFS mounted"


# ----------------------------------------
# 4. 테스트 파일
# ----------------------------------------

TEST_FILE="$MOUNT_DIR/simple_test.txt"
RENAMED_FILE="$MOUNT_DIR/simple_test_renamed.txt"

UNDERLAY_TEST="$UNDERLAY_DIR/simple_test.txt"
UNDERLAY_RENAMED="$UNDERLAY_DIR/simple_test_renamed.txt"


# ----------------------------------------
# 5. 이전 테스트 데이터 제거
# ----------------------------------------

rm -f "$UNDERLAY_TEST"
rm -f "$UNDERLAY_RENAMED"

echo "[OK] Previous test files cleaned"


# ========================================
# TEST 1 - CREATE + WRITE
# ========================================

echo ""
echo "[TEST 1] CREATE + WRITE"

echo "GuardFS simple test" > "$TEST_FILE"

sleep 0.2

if [ -f "$UNDERLAY_TEST" ]; then
    echo "[PASS] CREATE + WRITE"
else
    echo "[FAIL] CREATE + WRITE"
    exit 1
fi


# ========================================
# TEST 2 - READ
# ========================================

echo ""
echo "[TEST 2] READ"

CONTENT=$(cat "$TEST_FILE")

if [ "$CONTENT" = "GuardFS simple test" ]; then
    echo "[PASS] READ"
else
    echo "[FAIL] READ"
    exit 1
fi


# ========================================
# TEST 3 - RENAME
# ========================================

echo ""
echo "[TEST 3] RENAME"

mv "$TEST_FILE" "$RENAMED_FILE"

sleep 0.2

if [ -f "$UNDERLAY_RENAMED" ]; then
    echo "[PASS] RENAME"
else
    echo "[FAIL] RENAME"
    exit 1
fi


# ========================================
# TEST 4 - UNLINK
# ========================================

echo ""
echo "[TEST 4] UNLINK"

rm "$RENAMED_FILE"

sleep 0.2

if [ ! -e "$UNDERLAY_RENAMED" ]; then
    echo "[PASS] UNLINK"
else
    echo "[FAIL] UNLINK"
    exit 1
fi


# ========================================
# TEST 5 - HONEYPOT
# ========================================

echo ""
echo "[TEST 5] HONEYPOT"

HONEYPOT_UNDERLAY="$UNDERLAY_DIR/honeypot"
HONEYPOT_FILE="$MOUNT_DIR/honeypot/decoy.txt"

# FUSE의 mkdir을 사용하지 않고 underlay에서 직접 준비
mkdir -p "$HONEYPOT_UNDERLAY"

echo "GuardFS Honeypot Decoy" \
    > "$HONEYPOT_UNDERLAY/decoy.txt"

echo "[INFO] Accessing honeypot..."

# 탐지/차단되어도 테스트 스크립트 전체는 종료하지 않음
cat "$HONEYPOT_FILE" >/dev/null 2>&1 || true

sleep 0.5

echo "[OK] Honeypot access generated"


# ========================================
# 완료
# ========================================

echo ""
echo "========================================"
echo " GuardFS Simple Test Finished"
echo "========================================"

echo ""
echo "확인할 항목:"
echo "  CREATE + WRITE"
echo "  READ"
echo "  RENAME"
echo "  UNLINK"
echo "  HONEYPOT"
echo ""
echo "GuardFS 터미널에서 HoneypotDetector 로그를 확인하세요."