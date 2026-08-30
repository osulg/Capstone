#!/usr/bin/env bash

# GuardFS Honeypot 실제 FUSE 동작 기준선 테스트
#
# - GuardFS가 실행 중이고 MOUNT가 연결된 Linux 환경에서 실행
# - 실제 mount 경로에서 cat/open/read를 수행하여 파일 내용이 노출되는지와
#   underlay 원본이 보존되는지를 확인
#
# 실행 예:
#   ./scripts/stage1/test_honeypot_behavior.sh
#   MOUNT=/path/to/mount UNDERLAY=/path/to/underlay \
#       ./scripts/stage1/test_honeypot_behavior.sh
#
# 주의:
#   - HIGH 정책이 테스트 프로세스를 SIGSTOP할 수 있으므로 read 테스트에는 timeout을 사용
#   - 스크립트는 정책을 강제로 HIGH로 바꾸지 않기
#   - Stage 1/Stage 2의 실제 전이 결과에 따라 read가 허용될 수 있으며 현재 동작의 기준선으로 기록

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

usage() {
    echo "Usage: $0 [all|1|2|3|4|5|6]"
    echo "  1  honeypot cat 내용 노출/차단"
    echo "  2  Python open/read 차단"
    echo "  3  열린 file handle read 차단"
    echo "  4  정상 파일 오탐 방지"
    echo "  5  underlay 원본 보존"
    echo "  6  테스트 후 GuardFS/mount 생존"
}

if [[ "$TEST_NO" != "all" && ! "$TEST_NO" =~ ^[1-6]$ ]]; then
    usage
    exit 2
fi

run_test() {
    [ "$TEST_NO" = "all" ] || [ "$TEST_NO" = "$1" ]
}

record() {
    local status="$1"
    local name="$2"
    local detail="$3"

    case "$status" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        SKIP) SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
    esac

    # 결과 파일은 후처리하기 쉽도록 pipe 구분 형식으로 기록한다.
    detail="${detail//$'\n'/ }"
    detail="${detail//|//}"
    printf '%s|%s|%s\n' "$status" "$name" "$detail" >> "$RESULT_FILE"
}

cleanup() {
    # 이 테스트가 만든 파일만 제거한다. 기존 사용자 파일은 건드리지 않는다.
    rm -f -- "$UNDERLAY_HONEYPOT_FILE" "$UNDERLAY_NORMAL_FILE" \
        "$MOUNT_HONEYPOT_FILE" "$MOUNT_NORMAL_FILE" 2>/dev/null || true
    rmdir -- "$UNDERLAY_HONEYPOT_DIR" "$UNDERLAY_NORMAL_DIR" \
        "$TEST_ROOT" 2>/dev/null || true
    rm -f -- "$RESULT_FILE"
}

trap cleanup EXIT INT TERM

UNDERLAY_HONEYPOT_DIR="$UNDERLAY/honeypot"
UNDERLAY_NORMAL_DIR="$TEST_ROOT/normal"
UNDERLAY_HONEYPOT_FILE="$UNDERLAY_HONEYPOT_DIR/trap_$STAMP.txt"
UNDERLAY_NORMAL_FILE="$UNDERLAY_NORMAL_DIR/report.txt"

# mount는 underlay와 같은 상대 구조를 노출하므로 테스트용 하위 디렉터리를
# 두 경로에 동일하게 만든다.
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

# 1) cat 기준선: 현재 구현에서 실제 내용이 출력되는지 기록한다.
if run_test 1; then
CAT_OUTPUT_FILE="$(mktemp /tmp/guardfs-honeypot-cat.XXXXXX)"
if timeout 5 cat "$MOUNT_HONEYPOT_FILE" > "$CAT_OUTPUT_FILE" 2>"$CAT_OUTPUT_FILE.err"; then
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

# 2) Python open/read: cat 내부 동작을 단순화해 open/read 단계 결과를 기록한다.
if run_test 2; then
READ_OUTPUT_FILE="$(mktemp /tmp/guardfs-honeypot-read.XXXXXX)"
if timeout 5 python3 - "$MOUNT_HONEYPOT_FILE" > "$READ_OUTPUT_FILE" 2>&1 <<'PY'
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

# 3) 열린 file handle 기준선: handle 발급 후 read가 계속 가능한지 기록한다.
if run_test 3; then
HANDLE_OUTPUT_FILE="$(mktemp /tmp/guardfs-honeypot-handle.XXXXXX)"
if timeout 5 python3 - "$MOUNT_HONEYPOT_FILE" > "$HANDLE_OUTPUT_FILE" 2>&1 <<'PY'
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

# 4) 정상 파일이 honeypot 정책에 의해 잘못 막히지 않는지 확인한다.
if run_test 4; then
NORMAL_OUTPUT="$(timeout 5 cat "$MOUNT_NORMAL_FILE" 2>/dev/null || true)"
if [ "$NORMAL_OUTPUT" = "$ORIGINAL_NORMAL_CONTENT" ]; then
    record "PASS" "Normal file remains readable" "normal content returned"
else
    record "FAIL" "Normal file remains readable" "expected=$ORIGINAL_NORMAL_CONTENT actual=$NORMAL_OUTPUT"
fi
fi

# 5) honeypot read 실험이 원본 underlay를 변경하지 않았는지 확인한다.
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

# 6) read 테스트가 GuardFS userspace 프로세스를 종료시키지 않았는지 확인한다.
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
