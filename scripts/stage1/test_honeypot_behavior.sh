#!/usr/bin/env bash

# GuardFS 허니팟 FUSE 동작 테스트
# GuardFS가 실행 중이고 MOUNT가 연결된 Linux 환경에서 실행한다.
# 마운트 경로에서 파일을 읽거나 변경하여 허니팟 접근 차단 여부와
# 언더레이 원본 보존 여부를 확인한다.
#
# 실행 예시
#   ./scripts/stage1/test_honeypot_behavior.sh
#   MOUNT=/path/to/mount UNDERLAY=/path/to/underlay \
#       ./scripts/stage1/test_honeypot_behavior.sh
#
# 주의:
#   - HIGH 정책은 테스트 프로세스를 SIGSTOP할 수 있으므로 FUSE 명령을 별도 프로세스 그룹에서 실행한다.
#   - 이 스크립트는 프로세스 상태를 강제로 HIGH로 변경하지 않는다.
#   - Stage 1/Stage 2의 실제 판정 결과에 따라 읽기가 허용될 수 있으며, 현재 정책을 기준으로 결과를 기록한다.

set -u

MOUNT="${MOUNT:-$HOME/guardfs_runtime/mount}"
UNDERLAY="${UNDERLAY:-$HOME/guardfs_runtime/underlay}"
TEST_NO="${1:-all}"
STAMP="$(date +%Y%m%d_%H%M%S)_$$"
TEST_ROOT="$UNDERLAY/.guardfs_honeypot_behavior_$STAMP"
RESULT_FILE="$(mktemp /tmp/guardfs-honeypot-result.XXXXXX)"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
EXTRA_FILES=()

usage() {
    echo "Usage: $0 [all|1-13]"
    echo "  1  허니팟 cat 내용 노출/차단"
    echo "  2  Python open/read 차단"
    echo "  3  열린 file handle read 차단"
    echo "  4  정상 파일 오탐 방지"
    echo "  5  underlay 원본 보존"
    echo "  6  테스트 후 GuardFS/mount 생존"
    echo "  7  허니팟 write 차단"
    echo "  8  허니팟 truncate 차단"
    echo "  9  허니팟 ftruncate 차단"
    echo " 10  허니팟 unlink 차단"
    echo " 11  허니팟 rename 차단"
    echo " 12  열린 핸들의 write 차단"
    echo " 13  열린 핸들의 ftruncate 차단"
}

if [[ "$TEST_NO" != "all" && ! "$TEST_NO" =~ ^(1[0-3]|[1-9])$ ]]; then
    usage
    exit 2
fi

run_test() {
    [ "$TEST_NO" = "all" ] || [ "$TEST_NO" = "$1" ] || return 1
    # 7~13번은 언더레이 허니팟 디렉터리에 테스트 파일을 만들 수 있어야 한다.
    # 디렉터리가 잠겨 있으면 해당 변경 테스트를 실행하지 않고 건너뛴다.
    if [ "$1" -ge 7 ]; then
        # 권한 비트만으로는 FUSE/ACL 상태를 정확히 알 수 없으므로 실제 확인용 파일을
        # 잠시 생성한다. 생성에 실패해도 스크립트의 나머지 테스트는 계속 진행한다.
        if ! timeout 2 sh -c 'p="$1/.guardfs_mutation_probe_$$"; : > "$p" && rm -f -- "$p"' sh "$UNDERLAY_HONEYPOT_DIR" 2>/dev/null; then
            echo "SKIP [TEST $1] honeypot mutation: underlay directory is not writable"
            return 1
        fi
    fi
    return 0
}

run_fuse_command() {
    local limit_seconds="$1"
    local command_pid
    local watchdog_pid
    local command_rc=0
    shift

    # HIGH 정책이 명령을 SIGSTOP해도 감시 프로세스는 별도 그룹에서 계속 동작한다.
    # 제한 시간이 지나면 정지 상태를 해제한 뒤 전체 명령 그룹을 종료한다.
    setsid -- "$@" <&0 &
    command_pid=$!

    (
        sleep "$limit_seconds"
        kill -CONT -- "-$command_pid" 2>/dev/null || true
        kill -TERM -- "-$command_pid" 2>/dev/null || true
        sleep 1
        kill -CONT -- "-$command_pid" 2>/dev/null || true
        kill -KILL -- "-$command_pid" 2>/dev/null || true
    ) &
    watchdog_pid=$!

    wait "$command_pid" || command_rc=$?
    kill "$watchdog_pid" 2>/dev/null || true
    wait "$watchdog_pid" 2>/dev/null || true

    return "$command_rc"
}

record() {
    local status="$1"
    local name="$2"
    local detail="$3"
    local label="[COMMON]"

    case "$name" in
        *"Honeypot cat"*|*"Honeypot content"*) label="[TEST 1]" ;;
        *"Honeypot open/read"*) label="[TEST 2]" ;;
        *"Opened handle read"*) label="[TEST 3]" ;;
        *"Normal file"*) label="[TEST 4]" ;;
        *"Underlay honeypot"*|*"Underlay normal fixture"*) label="[TEST 5]" ;;
        *"Final GuardFS health"*) label="[TEST 6]" ;;
        *"Honeypot write"*) label="[TEST 7]" ;;
        *"Honeypot truncate"*) label="[TEST 8]" ;;
        *"Honeypot ftruncate"*) label="[TEST 9]" ;;
        *"Honeypot unlink"*) label="[TEST 10]" ;;
        *"Honeypot rename"*) label="[TEST 11]" ;;
        *"Opened handle write"*) label="[TEST 12]" ;;
        *"Opened handle ftruncate"*) label="[TEST 13]" ;;
    esac

    case "$status" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        SKIP) SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
    esac

    # 결과 파일 파싱을 위해 줄바꿈과 구분 문자를 정리한다.
    detail="${detail//$'\n'/ }"
    detail="${detail//|//}"
    printf '%s|%s %s|%s\n' "$status" "$label" "$name" "$detail" >> "$RESULT_FILE"
}

cleanup() {
    # 이번 실행에서 생성한 파일만 정리한다. 기존 사용자 파일은 삭제하지 않는다.
    # FUSE 정리 명령이 멈추지 않도록 안전 실행 함수를 사용하며, 정리 실패는 무시한다.
    run_fuse_command 3 rm -f -- "$UNDERLAY_HONEYPOT_FILE" "$UNDERLAY_NORMAL_FILE" \
        "$MOUNT_HONEYPOT_FILE" "$MOUNT_NORMAL_FILE" 2>/dev/null || true
    run_fuse_command 3 rmdir -- "$UNDERLAY_HONEYPOT_DIR" "$UNDERLAY_NORMAL_DIR" \
        "$TEST_ROOT" 2>/dev/null || true
    for extra in "${EXTRA_FILES[@]}"; do
        rm -f -- "$extra" 2>/dev/null || true
    done
    rm -f -- "$RESULT_FILE"
}

trap cleanup EXIT INT TERM

UNDERLAY_HONEYPOT_DIR="$UNDERLAY/honeypot"
UNDERLAY_NORMAL_DIR="$TEST_ROOT/normal"
UNDERLAY_HONEYPOT_FILE="$UNDERLAY_HONEYPOT_DIR/trap_$STAMP.txt"
UNDERLAY_NORMAL_FILE="$UNDERLAY_NORMAL_DIR/report.txt"

# 마운트와 언더레이에서 동일한 테스트 구조를 사용하도록 경로를 설정한다.
MOUNT_HONEYPOT_FILE="$MOUNT/honeypot/trap_$STAMP.txt"
MOUNT_NORMAL_FILE="$MOUNT/.guardfs_honeypot_behavior_$STAMP/normal/report.txt"

echo "GuardFS Honeypot behavior test"
echo "MOUNT   : $MOUNT"
echo "UNDERLAY: $UNDERLAY"
echo "TEST ID : $STAMP"
echo

if ! command -v mountpoint >/dev/null 2>&1; then
    record "SKIP" "Precheck mountpoint command" "mountpoint command unavailable"
elif mountpoint -q "$MOUNT"; then
    record "PASS" "Precheck mount" "connected"
else
    record "FAIL" "Precheck mount" "not mounted: $MOUNT"
fi

GUARDFS_PID="$(pgrep -f '[p]ython3 .*guardfs/fuse_fs/passthrough.py' | head -n 1 || true)"
if [ -n "$GUARDFS_PID" ]; then
    record "PASS" "Precheck GuardFS process" "PID=$GUARDFS_PID"
else
    record "FAIL" "Precheck GuardFS process" "passthrough.py is not running"
fi

if ! mountpoint -q "$MOUNT" 2>/dev/null || [ -z "$GUARDFS_PID" ]; then
    echo "Precheck failed; no FUSE operation was executed."
    exit 1
fi

mkdir -p -- "$UNDERLAY_HONEYPOT_DIR" "$UNDERLAY_NORMAL_DIR"
printf 'HONEYPOT-ORIGINAL-%s\n' "$STAMP" > "$UNDERLAY_HONEYPOT_FILE"
printf 'NORMAL-ORIGINAL-%s\n' "$STAMP" > "$UNDERLAY_NORMAL_FILE"

ORIGINAL_HONEYPOT_CONTENT="$(cat "$UNDERLAY_HONEYPOT_FILE")"
ORIGINAL_NORMAL_CONTENT="$(cat "$UNDERLAY_NORMAL_FILE")"

# 허니팟 픽스처를 만든 직후 언더레이 디렉터리의 쓰기 권한을 확인한다.
# 쓸 수 없으면 7~13번 테스트용 파일을 언더레이에 만들 수 없으므로 해당 테스트를
# SKIP으로 기록한다. 읽기 차단(1~3번)과 정상 경로 및 상태 확인(4~6번)은 계속 실행한다.
if [ -w "$UNDERLAY_HONEYPOT_DIR" ]; then
    HONEYPOT_MUTATION_ALLOWED=1
else
    HONEYPOT_MUTATION_ALLOWED=0
    echo "WARNING: honeypot underlay directory is not writable; tests 7-13 will be skipped."
fi

skip_mutation_test() {
    local number="$1"
    local name="$2"
    if [ "$HONEYPOT_MUTATION_ALLOWED" -ne 1 ]; then
        record "SKIP" "$name" "honeypot underlay directory is not writable"
        return 0
    fi
    return 1
}

if [ -f "$MOUNT_HONEYPOT_FILE" ]; then
    record "PASS" "Honeypot fixture visible" "$MOUNT_HONEYPOT_FILE"
else
    record "FAIL" "Honeypot fixture visible" "mount path is missing"
fi

if [ -f "$MOUNT_NORMAL_FILE" ]; then
    record "PASS" "Normal fixture visible" "$MOUNT_NORMAL_FILE"
else
    record "FAIL" "Normal fixture visible" "mount path is missing"
fi

# 1) cat으로 허니팟을 읽었을 때 실제 내용이 노출되거나 접근이 차단되는지 확인한다.
if run_test 1; then
CAT_OUTPUT_FILE="$(mktemp /tmp/guardfs-honeypot-cat.XXXXXX)"
if run_fuse_command 5 cat "$MOUNT_HONEYPOT_FILE" > "$CAT_OUTPUT_FILE" 2>"$CAT_OUTPUT_FILE.err"; then
    CAT_RC=0
else
    CAT_RC=$?
fi
CAT_OUTPUT="$(<"$CAT_OUTPUT_FILE")"
CAT_ERROR="$(<"$CAT_OUTPUT_FILE.err")"
rm -f -- "$CAT_OUTPUT_FILE" "$CAT_OUTPUT_FILE.err"

if [ "$CAT_RC" -eq 0 ]; then
    record "FAIL" "Honeypot cat blocked" "cat succeeded; output=$CAT_OUTPUT"
else
    record "PASS" "Honeypot cat blocked" "cat failed; rc=$CAT_RC error=$CAT_ERROR"
fi

if [ "$CAT_OUTPUT" = "$ORIGINAL_HONEYPOT_CONTENT" ]; then
    record "FAIL" "Honeypot content not exposed" "real underlay content was returned"
elif [ -z "$CAT_OUTPUT" ]; then
    record "PASS" "Honeypot content not exposed" "no content returned"
else
    record "PASS" "Honeypot content not exposed" "non-original output returned"
fi
fi

# 2) Python open/read로 cat과 같은 읽기 동작을 수행하고 단계별 결과를 확인한다.
if run_test 2; then
READ_OUTPUT_FILE="$(mktemp /tmp/guardfs-honeypot-read.XXXXXX)"
if run_fuse_command 5 python3 - "$MOUNT_HONEYPOT_FILE" > "$READ_OUTPUT_FILE" 2>&1 <<'PY'
import sys

path = sys.argv[1]
try:
    with open(path, "rb") as handle:
        data = handle.read()
    print("READ_SUCCESS", repr(data))
except OSError as exc:
    print("READ_ERROR", exc.errno, str(exc))
    raise SystemExit(1)
PY
then
    READ_RC=0
else
    READ_RC=$?
fi
READ_OUTPUT="$(<"$READ_OUTPUT_FILE")"
rm -f -- "$READ_OUTPUT_FILE"

if [[ "$READ_OUTPUT" == READ_ERROR* ]]; then
    record "PASS" "Honeypot open/read rejected" "$READ_OUTPUT"
elif [[ "$READ_OUTPUT" == *"$ORIGINAL_HONEYPOT_CONTENT"* ]]; then
    record "FAIL" "Honeypot open/read rejected" "real content returned; rc=$READ_RC"
else
    record "FAIL" "Honeypot open/read rejected" "read succeeded or unexpected output=$READ_OUTPUT"
fi
fi

# 3) 열린 파일 핸들을 통해 읽기가 계속 가능한지 확인한다.
if run_test 3; then
HANDLE_OUTPUT_FILE="$(mktemp /tmp/guardfs-honeypot-handle.XXXXXX)"
if run_fuse_command 5 python3 - "$MOUNT_HONEYPOT_FILE" > "$HANDLE_OUTPUT_FILE" 2>&1 <<'PY'
import sys

path = sys.argv[1]
try:
    handle = open(path, "rb")
    data = handle.read()
    handle.close()
    print("HANDLE_READ_SUCCESS", repr(data))
except OSError as exc:
    print("HANDLE_READ_ERROR", exc.errno, str(exc))
    raise SystemExit(1)
PY
then
    HANDLE_RC=0
else
    HANDLE_RC=$?
fi
HANDLE_OUTPUT="$(<"$HANDLE_OUTPUT_FILE")"
rm -f -- "$HANDLE_OUTPUT_FILE"

if [[ "$HANDLE_OUTPUT" == *"$ORIGINAL_HONEYPOT_CONTENT"* ]]; then
    record "FAIL" "Opened handle read blocked" "real content returned; rc=$HANDLE_RC"
elif [[ "$HANDLE_OUTPUT" == HANDLE_READ_ERROR* ]]; then
    record "PASS" "Opened handle read blocked" "$HANDLE_OUTPUT"
else
    record "FAIL" "Opened handle read blocked" "unexpected output=$HANDLE_OUTPUT"
fi
fi

# 4) 정상 파일이 허니팟 정책으로 인해 잘못 차단되지 않는지 확인한다.
if run_test 4; then
NORMAL_OUTPUT="$(run_fuse_command 5 cat "$MOUNT_NORMAL_FILE" 2>/dev/null || true)"
if [ "$NORMAL_OUTPUT" = "$ORIGINAL_NORMAL_CONTENT" ]; then
    record "PASS" "Normal file remains readable" "normal content returned"
else
    record "FAIL" "Normal file remains readable" "expected=$ORIGINAL_NORMAL_CONTENT actual=$NORMAL_OUTPUT"
fi
fi

# 5) 허니팟 읽기 테스트가 언더레이 원본을 변경하지 않았는지 확인한다.
if run_test 5; then
AFTER_HONEYPOT_CONTENT="$(cat "$UNDERLAY_HONEYPOT_FILE" 2>/dev/null || true)"
if [ "$AFTER_HONEYPOT_CONTENT" = "$ORIGINAL_HONEYPOT_CONTENT" ]; then
    record "PASS" "Underlay honeypot preserved" "unchanged"
else
    record "FAIL" "Underlay honeypot preserved" "content changed"
fi

AFTER_NORMAL_CONTENT="$(cat "$UNDERLAY_NORMAL_FILE" 2>/dev/null || true)"
if [ "$AFTER_NORMAL_CONTENT" = "$ORIGINAL_NORMAL_CONTENT" ]; then
    record "PASS" "Underlay normal fixture preserved" "unchanged"
else
    record "FAIL" "Underlay normal fixture preserved" "content changed"
fi
fi

# 7) 허니팟 write: 접근만 차단하고 실제 언더레이 변경도 막는지 확인한다.
if run_test 7; then
WRITE_FILE="$UNDERLAY_HONEYPOT_DIR/write_$STAMP.txt"
EXTRA_FILES+=("$WRITE_FILE")
printf 'WRITE-ORIGINAL-%s\n' "$STAMP" > "$WRITE_FILE"
WRITE_ORIGINAL="$(cat "$WRITE_FILE")"
# 별도 셸에서 리다이렉션을 수행하여 bash 자체의 Permission denied 메시지도 숨긴다.
run_fuse_command 5 sh -c 'printf "WRITE-ATTEMPT-%s\\n" "$1" > "$2"' sh "$STAMP" \
    "$MOUNT/honeypot/write_$STAMP.txt" >/dev/null 2>&1 || true
WRITE_AFTER="$(cat "$WRITE_FILE" 2>/dev/null || true)"
if [ "$WRITE_AFTER" = "$WRITE_ORIGINAL" ]; then
    record "PASS" "Honeypot write blocked" "underlay unchanged"
else
    record "FAIL" "Honeypot write blocked" "underlay content changed"
fi
fi

# 8) 허니팟 truncate: 파일 크기 변경이 차단되는지 확인한다.
if run_test 8; then
TRUNC_FILE="$UNDERLAY_HONEYPOT_DIR/truncate_$STAMP.txt"
EXTRA_FILES+=("$TRUNC_FILE")
printf 'TRUNCATE-ORIGINAL-%s\n' "$STAMP" > "$TRUNC_FILE"
TRUNC_ORIGINAL="$(cat "$TRUNC_FILE")"
run_fuse_command 5 truncate -s 0 "$MOUNT/honeypot/truncate_$STAMP.txt" 2>/dev/null || true
TRUNC_AFTER="$(cat "$TRUNC_FILE" 2>/dev/null || true)"
if [ "$TRUNC_AFTER" = "$TRUNC_ORIGINAL" ]; then
    record "PASS" "Honeypot truncate blocked" "underlay unchanged"
else
    record "FAIL" "Honeypot truncate blocked" "underlay content changed"
fi
fi

# 9) 허니팟 ftruncate: 열린 파일 핸들을 통한 크기 변경 우회를 차단하는지 확인한다.
if run_test 9; then
FTRUNC_FILE="$UNDERLAY_HONEYPOT_DIR/ftruncate_$STAMP.txt"
EXTRA_FILES+=("$FTRUNC_FILE")
printf 'FTRUNCATE-ORIGINAL-%s\n' "$STAMP" > "$FTRUNC_FILE"
FTRUNC_ORIGINAL="$(cat "$FTRUNC_FILE")"
run_fuse_command 5 python3 - "$MOUNT/honeypot/ftruncate_$STAMP.txt" <<'PY' 2>/dev/null || true
import os
import sys
path = sys.argv[1]
try:
    fd = os.open(path, os.O_RDWR)
    os.ftruncate(fd, 0)
    os.close(fd)
except OSError:
    pass
PY
FTRUNC_AFTER="$(cat "$FTRUNC_FILE" 2>/dev/null || true)"
if [ "$FTRUNC_AFTER" = "$FTRUNC_ORIGINAL" ]; then
    record "PASS" "Honeypot ftruncate blocked" "underlay unchanged"
else
    record "FAIL" "Honeypot ftruncate blocked" "underlay content changed"
fi
fi

# 10) 허니팟 unlink: 실제 파일 삭제가 차단되는지 확인한다.
if run_test 10; then
UNLINK_FILE="$UNDERLAY_HONEYPOT_DIR/unlink_$STAMP.txt"
EXTRA_FILES+=("$UNLINK_FILE")
printf 'UNLINK-ORIGINAL-%s\n' "$STAMP" > "$UNLINK_FILE"
run_fuse_command 5 rm -f -- "$MOUNT/honeypot/unlink_$STAMP.txt" 2>/dev/null || true
if [ -f "$UNLINK_FILE" ]; then
    record "PASS" "Honeypot unlink blocked" "underlay file remains"
else
    record "FAIL" "Honeypot unlink blocked" "underlay file deleted"
fi
fi

# 11) 허니팟 rename: 출발지나 목적지 중 하나라도 허니팟이면 이름 변경을 차단하는지 확인한다.
if run_test 11; then
RENAME_FILE="$UNDERLAY_HONEYPOT_DIR/rename_$STAMP.txt"
RENAME_TARGET="$UNDERLAY_NORMAL_DIR/renamed_$STAMP.txt"
EXTRA_FILES+=("$RENAME_FILE" "$RENAME_TARGET")
printf 'RENAME-ORIGINAL-%s\n' "$STAMP" > "$RENAME_FILE"
run_fuse_command 5 mv -- "$MOUNT/honeypot/rename_$STAMP.txt" \
    "$MOUNT/.guardfs_honeypot_behavior_$STAMP/normal/renamed_$STAMP.txt" \
    >/dev/null 2>&1 || true
if [ -f "$RENAME_FILE" ] && [ ! -f "$RENAME_TARGET" ]; then
    record "PASS" "Honeypot rename blocked" "source remains and target absent"
else
    record "FAIL" "Honeypot rename blocked" "rename reached underlay"
fi
fi

# 12) 열린 핸들의 write 우회: 핸들을 연 뒤 쓰기가 가능한지 확인한다.
if run_test 12; then
HANDLE_WRITE_FILE="$UNDERLAY_HONEYPOT_DIR/handle_write_$STAMP.txt"
EXTRA_FILES+=("$HANDLE_WRITE_FILE")
printf 'HANDLE-WRITE-ORIGINAL-%s\n' "$STAMP" > "$HANDLE_WRITE_FILE"
HANDLE_WRITE_ORIGINAL="$(cat "$HANDLE_WRITE_FILE")"
run_fuse_command 5 python3 - "$MOUNT/honeypot/handle_write_$STAMP.txt" <<'PY' 2>/dev/null || true
import sys
path = sys.argv[1]
try:
    with open(path, "r+b", buffering=0) as handle:
        handle.write(b"HANDLE-WRITE-ATTEMPT")
except OSError:
    pass
PY
if [ "$(cat "$HANDLE_WRITE_FILE" 2>/dev/null || true)" = "$HANDLE_WRITE_ORIGINAL" ]; then
    record "PASS" "Opened handle write blocked" "underlay unchanged"
else
    record "FAIL" "Opened handle write blocked" "underlay content changed"
fi
fi

# 13) 열린 핸들의 ftruncate 우회: 9번과 유사하지만 별도 시나리오로 결과를 기록한다.
if run_test 13; then
HANDLE_FTRUNC_FILE="$UNDERLAY_HONEYPOT_DIR/handle_ftruncate_$STAMP.txt"
EXTRA_FILES+=("$HANDLE_FTRUNC_FILE")
printf 'HANDLE-FTRUNCATE-ORIGINAL-%s\n' "$STAMP" > "$HANDLE_FTRUNC_FILE"
HANDLE_FTRUNC_ORIGINAL="$(cat "$HANDLE_FTRUNC_FILE")"
run_fuse_command 5 python3 - "$MOUNT/honeypot/handle_ftruncate_$STAMP.txt" <<'PY' 2>/dev/null || true
import os
import sys
path = sys.argv[1]
try:
    fd = os.open(path, os.O_RDWR)
    os.ftruncate(fd, 0)
    os.close(fd)
except OSError:
    pass
PY
if [ "$(cat "$HANDLE_FTRUNC_FILE" 2>/dev/null || true)" = "$HANDLE_FTRUNC_ORIGINAL" ]; then
    record "PASS" "Opened handle ftruncate blocked" "underlay unchanged"
else
    record "FAIL" "Opened handle ftruncate blocked" "underlay content changed"
fi
fi

# 6) 읽기 테스트 이후에도 GuardFS 사용자 공간 프로세스와 마운트가 정상인지 확인한다.
if run_test 6; then
FINAL_PID="$(pgrep -f '[p]ython3 .*guardfs/fuse_fs/passthrough.py' | head -n 1 || true)"
if [ -n "$FINAL_PID" ] && mountpoint -q "$MOUNT" 2>/dev/null; then
    record "PASS" "Final GuardFS health" "PID=$FINAL_PID mount=connected"
else
    record "FAIL" "Final GuardFS health" "process or mount disconnected"
fi
fi

echo
echo "============================================================"
echo " GuardFS Honeypot Behavior Test"
echo "============================================================"
while IFS='|' read -r status name detail; do
    printf '%-5s | %-34s | %s\n' "$status" "$name" "$detail"
done < "$RESULT_FILE"
echo "------------------------------------------------------------"
echo "PASS=$PASS_COUNT FAIL=$FAIL_COUNT SKIP=$SKIP_COUNT"
if [ "$FAIL_COUNT" -eq 0 ]; then
    echo "FINAL RESULT: PASS"
else
    echo "FINAL RESULT: FAIL"
fi
echo "============================================================"

[ "$FAIL_COUNT" -eq 0 ]
