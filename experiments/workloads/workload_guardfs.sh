#!/usr/bin/env bash
set -euo pipefail

# 사용법:
#   ./guardfs_workload.sh [대상_마운트_경로] [반복횟수]
#
# 예시:
#   ./guardfs_workload.sh ~/guardfs_lab/mount/Projects 300

TARGET_DIR="${1:-$HOME/guardfs_lab/mount/Projects}"
COUNT="${2:-100}"

WORK_DIR="$TARGET_DIR/normal_workload"
FILE_DIR="$WORK_DIR/files"
DIR_TEST_ROOT="$WORK_DIR/directories"
TRUNCATE_FILE="$WORK_DIR/truncate_test.bin"

LOG_DIR="$HOME/guardfs_lab/logs"
WORKLOAD_STATE_FILE="$LOG_DIR/.workload_state"

mkdir -p "$LOG_DIR"

set_workload_state() {
    local step="$1"
    local title="$2"

    printf "%s | %s\n" "$step" "$title" > "$WORKLOAD_STATE_FILE"

    echo
    echo "========================================================================"
    echo "[$step]"
    echo "$title"
    echo "========================================================================"
    echo
}

cleanup_on_exit() {
    local exit_code=$?

    if (( exit_code != 0 )); then
        echo
        echo "[ERROR] 워크로드가 중단되었습니다. exit_code=$exit_code"
        echo "[INFO] 잔여 경로: $WORK_DIR"
    fi
}
trap cleanup_on_exit EXIT

echo "========================================"
echo "GuardFS normal workload"
echo "Target : $TARGET_DIR"
echo "Count  : $COUNT"
echo "========================================"

if [[ ! -d "$TARGET_DIR" ]]; then
    echo "[ERROR] 대상 경로가 존재하지 않습니다: $TARGET_DIR"
    exit 1
fi

if ! [[ "$COUNT" =~ ^[1-9][0-9]*$ ]]; then
    echo "[ERROR] 반복횟수는 1 이상의 정수여야 합니다: $COUNT"
    exit 1
fi

# 이전 실험 잔여물 제거
# /usr/bin/rm을 직접 호출하여 alias, shell function, interactive 옵션 영향을 차단한다.
/usr/bin/rm -rf -- "$WORK_DIR"

# 작업 루트 생성
mkdir -- "$WORK_DIR"

# ------------------------------------------------------------
# STEP 1
# ------------------------------------------------------------
set_workload_state \
    "STEP 1 / 5" \
    "CREATE + WRITE + READ + GETATTR + RENAME + UNLINK"

mkdir -- "$FILE_DIR"

for i in $(seq 1 "$COUNT"); do
    ORIGINAL="$FILE_DIR/file_${i}.txt"
    RENAMED="$FILE_DIR/file_${i}.renamed"

    # create + open + write + release
    printf "normal workload data %06d\n" "$i" > "$ORIGINAL"

    # open + read + release
    cat -- "$ORIGINAL" > /dev/null

    # getattr/stat
    stat -- "$ORIGINAL" > /dev/null

    # rename
    mv -- "$ORIGINAL" "$RENAMED"

    # unlink: 쓰기 보호 파일이어도 질문 없이 삭제
    /usr/bin/rm -f -- "$RENAMED"
done

# ------------------------------------------------------------
# STEP 2
# ------------------------------------------------------------
set_workload_state \
    "STEP 2 / 5" \
    "MKDIR + CREATE + WRITE + READDIR + UNLINK + RMDIR"

mkdir -- "$DIR_TEST_ROOT"

for i in $(seq 1 "$COUNT"); do
    TEST_DIR="$DIR_TEST_ROOT/dir_${i}"

    # mkdir
    mkdir -- "$TEST_DIR"

    # create + write
    printf "directory test %06d\n" "$i" > "$TEST_DIR/item.txt"

    # opendir + readdir + releasedir
    ls -la -- "$TEST_DIR" > /dev/null

    # unlink: 쓰기 보호 파일이어도 질문 없이 삭제
    /usr/bin/rm -f -- "$TEST_DIR/item.txt"

    # rmdir
    rmdir -- "$TEST_DIR"
done

# ------------------------------------------------------------
# STEP 3
# ------------------------------------------------------------
set_workload_state \
    "STEP 3 / 5" \
    "CREATE + WRITE + TRUNCATE + READ + UNLINK"

# create + write
dd if=/dev/zero of="$TRUNCATE_FILE" bs=4096 count=16 status=none

for i in $(seq 1 "$COUNT"); do
    truncate -s 8192 "$TRUNCATE_FILE"
    truncate -s 65536 "$TRUNCATE_FILE"

    # read
    head -c 4096 "$TRUNCATE_FILE" > /dev/null
done

# unlink: 쓰기 보호 파일이어도 질문 없이 삭제
/usr/bin/rm -f -- "$TRUNCATE_FILE"

# ------------------------------------------------------------
# STEP 4
# ------------------------------------------------------------
set_workload_state \
    "STEP 4 / 5" \
    "OPENDIR + READDIR"

ls -la -- "$WORK_DIR" > /dev/null

# ------------------------------------------------------------
# STEP 5
# ------------------------------------------------------------
set_workload_state \
    "STEP 5 / 5" \
    "WORKLOAD CLEANUP: RMDIR"

rmdir -- "$FILE_DIR"
rmdir -- "$DIR_TEST_ROOT"
rmdir -- "$WORK_DIR"

printf "%s\n" \
    "COMPLETE | NORMAL WORKLOAD FINISHED" \
    > "$WORKLOAD_STATE_FILE"

# GuardFS가 COMPLETE 상태를 읽도록 마지막 이벤트 발생
stat -- "$TARGET_DIR" > /dev/null

echo
echo "[DONE] GuardFS 정상행위 워크로드 완료"
echo "필수 예상 연산:"
echo "  create, mkdir, rename, rmdir, unlink, write"
echo "추가 예상 연산:"
echo "  open, read, lookup, getattr, opendir, readdir, release, truncate"