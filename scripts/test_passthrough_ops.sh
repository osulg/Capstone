#!/usr/bin/env bash

set -u

MOUNT="${MOUNT:-$HOME/guardfs_runtime/mount}"
UNDERLAY="${UNDERLAY:-$HOME/guardfs_runtime/underlay}"
TEST_NO="${1:-}"
STAMP="$(date +%Y%m%d_%H%M%S)"

PASS_COUNT=0
FAIL_COUNT=0
RESULTS=""
ARTIFACT="none"

usage() {
    echo "Usage: $0 <test-number>"
    echo
    echo "  1  LOW MKDIR -> STAT -> RMDIR"
    echo "  2  LOW CREATE -> WRITE -> READ"
    echo "  3  LOW RENAME -> STAT -> READ"
    echo "  4  LOW RENAME -> UNLINK"
    echo "  5  LOW OPEN HANDLE -> RENAME"
    echo "  6  LOW OPEN HANDLE -> UNLINK"
    echo "  7  LOW TRUNCATE -> FTRUNCATE"
}

record() {
    local status="$1"
    local name="$2"
    local detail="$3"

    if [ "$status" = "PASS" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

    RESULTS="${RESULTS}${status}|${name}|${detail}"$'\n'
}

check_equal() {
    local name="$1"
    local expected="$2"
    local actual="$3"

    if [ "$expected" = "$actual" ]; then
        record "PASS" "$name" "$actual"
    else
        record "FAIL" "$name" "expected=$expected actual=$actual"
    fi
}

precheck() {
    if mountpoint -q "$MOUNT"; then
        record "PASS" "Precheck mount" "connected"
    else
        record "FAIL" "Precheck mount" "disconnected"
        return 1
    fi

    local pid
    pid="$(pgrep -f '[p]ython3 .*guardfs/fuse_fs/passthrough.py' | head -n 1)"
    if [ -n "$pid" ]; then
        record "PASS" "Precheck process" "PID=$pid"
    else
        record "FAIL" "Precheck process" "not running"
        return 1
    fi
}

final_health() {
    if mountpoint -q "$MOUNT"; then
        record "PASS" "Final mount health" "connected"
    else
        record "FAIL" "Final mount health" "disconnected"
    fi

    local pid
    pid="$(pgrep -f '[p]ython3 .*guardfs/fuse_fs/passthrough.py' | head -n 1)"
    if [ -n "$pid" ]; then
        record "PASS" "Final process health" "PID=$pid"
    else
        record "FAIL" "Final process health" "not running"
    fi
}

test_mkdir_rmdir() {
    local case_name="mkdir_test_$STAMP"
    local mount_path="$MOUNT/$case_name"
    local underlay_path="$UNDERLAY/$case_name"
    local mount_attr underlay_attr

    if mkdir "$mount_path" 2>/tmp/guardfs-test-error; then
        record "PASS" "MKDIR" "created"
    else
        record "FAIL" "MKDIR" "$(tr '\n' ' ' </tmp/guardfs-test-error)"
    fi

    if [ -d "$mount_path" ]; then
        mount_attr="$(stat -c '%i:%a:%u:%g:%F' "$mount_path" 2>/dev/null)"
        record "PASS" "Mount directory" "$mount_attr"
    else
        mount_attr=""
        record "FAIL" "Mount directory" "missing or inaccessible"
    fi

    if [ -d "$underlay_path" ]; then
        underlay_attr="$(stat -c '%i:%a:%u:%g:%F' "$underlay_path" 2>/dev/null)"
        record "PASS" "Underlay directory" "$underlay_attr"
    else
        underlay_attr=""
        record "FAIL" "Underlay directory" "missing"
    fi

    if [ -n "$mount_attr" ] && [ -n "$underlay_attr" ]; then
        check_equal "Directory attributes" "$underlay_attr" "$mount_attr"
    else
        record "FAIL" "Directory attributes" "comparison unavailable"
    fi

    if rmdir "$mount_path" 2>/tmp/guardfs-test-error; then
        record "PASS" "RMDIR" "removed"
    else
        record "FAIL" "RMDIR" "$(tr '\n' ' ' </tmp/guardfs-test-error)"
    fi

    if [ ! -e "$mount_path" ] && [ ! -e "$underlay_path" ]; then
        record "PASS" "Removal propagation" "absent on mount and underlay"
    else
        record "FAIL" "Removal propagation" "path remains"
        ARTIFACT="$mount_path"
    fi
}

test_create_write_read() {
    local file_name="file_test_$STAMP.txt"
    local mount_path="$MOUNT/$file_name"
    local underlay_path="$UNDERLAY/$file_name"
    local mount_content underlay_content mount_attr underlay_attr

    ARTIFACT="$mount_path"

    if printf 'hello guardfs\n' >"$mount_path" 2>/tmp/guardfs-test-error; then
        record "PASS" "CREATE + WRITE" "exit=0"
    else
        record "FAIL" "CREATE + WRITE" "$(tr '\n' ' ' </tmp/guardfs-test-error)"
    fi

    [ -f "$mount_path" ] \
        && record "PASS" "Mount file" "exists" \
        || record "FAIL" "Mount file" "missing"
    [ -f "$underlay_path" ] \
        && record "PASS" "Underlay file" "exists" \
        || record "FAIL" "Underlay file" "missing"

    mount_content="$(cat "$mount_path" 2>/tmp/guardfs-test-error)"
    if [ $? -eq 0 ]; then
        record "PASS" "Mount read" "content=$mount_content"
    else
        record "FAIL" "Mount read" "$(tr '\n' ' ' </tmp/guardfs-test-error)"
    fi

    underlay_content="$(cat "$underlay_path" 2>/tmp/guardfs-test-error)"
    if [ $? -eq 0 ]; then
        record "PASS" "Underlay read" "content=$underlay_content"
    else
        record "FAIL" "Underlay read" "$(tr '\n' ' ' </tmp/guardfs-test-error)"
    fi

    check_equal "File contents" "$underlay_content" "$mount_content"

    mount_attr="$(stat -c '%i:%s:%a:%u:%g:%F' "$mount_path" 2>/dev/null)"
    underlay_attr="$(stat -c '%i:%s:%a:%u:%g:%F' "$underlay_path" 2>/dev/null)"
    if [ -n "$mount_attr" ] && [ -n "$underlay_attr" ]; then
        check_equal "File attributes" "$underlay_attr" "$mount_attr"
    else
        record "FAIL" "File attributes" "comparison unavailable"
    fi

    if exec 3<"$mount_path"; then
        local line=""
        IFS= read -r line <&3
        local read_rc=$?
        exec 3<&-
        if [ "$read_rc" -eq 0 ]; then
            check_equal "Reopen + read" "hello guardfs" "$line"
        else
            record "FAIL" "Reopen + read" "read failed"
        fi
    else
        record "FAIL" "Reopen + read" "open failed"
    fi
}

test_rename_stat_read() {
    local old_name="rename_test_${STAMP}_old.txt"
    local new_name="rename_test_${STAMP}_new.txt"
    local old_mount="$MOUNT/$old_name"
    local old_underlay="$UNDERLAY/$old_name"
    local new_mount="$MOUNT/$new_name"
    local new_underlay="$UNDERLAY/$new_name"
    local old_mount_inode old_underlay_inode new_mount_inode new_underlay_inode
    local mount_content underlay_content

    ARTIFACT="$new_mount"

    if printf 'rename test data\n' >"$old_mount" 2>/tmp/guardfs-test-error; then
        record "PASS" "Create source" "exit=0"
    else
        record "FAIL" "Create source" "$(tr '\n' ' ' </tmp/guardfs-test-error)"
    fi

    old_mount_inode="$(stat -c '%i' "$old_mount" 2>/dev/null)"
    old_underlay_inode="$(stat -c '%i' "$old_underlay" 2>/dev/null)"

    if mv "$old_mount" "$new_mount" 2>/tmp/guardfs-test-error; then
        record "PASS" "RENAME" "exit=0"
    else
        record "FAIL" "RENAME" "$(tr '\n' ' ' </tmp/guardfs-test-error)"
    fi

    if [ ! -e "$old_mount" ] && [ ! -e "$old_underlay" ]; then
        record "PASS" "Old paths" "removed"
    else
        record "FAIL" "Old paths" "still present"
    fi

    new_mount_inode="$(stat -c '%i' "$new_mount" 2>/dev/null)"
    new_underlay_inode="$(stat -c '%i' "$new_underlay" 2>/dev/null)"

    [ -n "$new_mount_inode" ] \
        && record "PASS" "New mount path" "inode=$new_mount_inode" \
        || record "FAIL" "New mount path" "missing or inaccessible"
    [ -n "$new_underlay_inode" ] \
        && record "PASS" "New underlay path" "inode=$new_underlay_inode" \
        || record "FAIL" "New underlay path" "missing"

    check_equal \
        "Mount inode continuity" \
        "$old_mount_inode" \
        "$new_mount_inode"
    check_equal \
        "Underlay inode continuity" \
        "$old_underlay_inode" \
        "$new_underlay_inode"

    mount_content="$(cat "$new_mount" 2>/tmp/guardfs-test-error)"
    if [ $? -eq 0 ]; then
        record "PASS" "Mount read after rename" "content=$mount_content"
    else
        record "FAIL" "Mount read after rename" "$(tr '\n' ' ' </tmp/guardfs-test-error)"
    fi

    underlay_content="$(cat "$new_underlay" 2>/tmp/guardfs-test-error)"
    if [ $? -eq 0 ]; then
        record "PASS" "Underlay read after rename" "content=$underlay_content"
    else
        record "FAIL" "Underlay read after rename" "$(tr '\n' ' ' </tmp/guardfs-test-error)"
    fi

    check_equal "Content after rename" "$underlay_content" "$mount_content"
}

test_rename_unlink() {
    local old_name="rename_unlink_${STAMP}_old.txt"
    local new_name="rename_unlink_${STAMP}_new.txt"
    local old_mount="$MOUNT/$old_name"
    local old_underlay="$UNDERLAY/$old_name"
    local new_mount="$MOUNT/$new_name"
    local new_underlay="$UNDERLAY/$new_name"

    ARTIFACT="$new_mount"

    if printf 'rename then unlink\n' >"$old_mount" 2>/tmp/guardfs-test-error; then
        record "PASS" "Create source" "exit=0"
    else
        record "FAIL" "Create source" "$(tr '\n' ' ' </tmp/guardfs-test-error)"
    fi

    if mv "$old_mount" "$new_mount" 2>/tmp/guardfs-test-error; then
        record "PASS" "RENAME" "exit=0"
    else
        record "FAIL" "RENAME" "$(tr '\n' ' ' </tmp/guardfs-test-error)"
    fi

    if [ -f "$new_mount" ] && [ -f "$new_underlay" ]; then
        record "PASS" "Renamed paths" "present on mount and underlay"
    else
        record "FAIL" "Renamed paths" "missing before unlink"
    fi

    if /bin/rm -f -- "$new_mount" 2>/tmp/guardfs-test-error; then
        record "PASS" "UNLINK after rename" "exit=0"
    else
        record \
            "FAIL" \
            "UNLINK after rename" \
            "$(tr '\n' ' ' </tmp/guardfs-test-error)"
    fi

    if [ ! -e "$old_mount" ] && [ ! -e "$old_underlay" ] &&
       [ ! -e "$new_mount" ] && [ ! -e "$new_underlay" ]; then
        record "PASS" "Unlink propagation" "all old and new paths absent"
        ARTIFACT="none"
    else
        record "FAIL" "Unlink propagation" "one or more paths remain"
    fi
}

test_open_handle_rename() {
    local old_name="open_rename_${STAMP}_old.txt"
    local new_name="open_rename_${STAMP}_new.txt"
    local old_mount="$MOUNT/$old_name"
    local old_underlay="$UNDERLAY/$old_name"
    local new_mount="$MOUNT/$new_name"
    local new_underlay="$UNDERLAY/$new_name"
    local python_output expected_content mount_content underlay_content

    ARTIFACT="$new_mount"
    export GUARDFS_TEST_OLD="$old_mount"
    export GUARDFS_TEST_NEW="$new_mount"

    python_output="$(python3 - <<'PY' 2>/tmp/guardfs-test-error
import os

old_path = os.environ["GUARDFS_TEST_OLD"]
new_path = os.environ["GUARDFS_TEST_NEW"]

with open(old_path, "w+b") as handle:
    handle.write(b"before rename\n")
    handle.flush()
    inode_before = os.fstat(handle.fileno()).st_ino
    os.rename(old_path, new_path)
    handle.seek(0)
    before = handle.read()
    handle.seek(0, os.SEEK_END)
    handle.write(b"after rename\n")
    handle.flush()
    inode_after = os.fstat(handle.fileno()).st_ino
    handle.seek(0)
    final = handle.read()

if before != b"before rename\n":
    raise RuntimeError(f"unexpected pre-append content: {before!r}")
if final != b"before rename\nafter rename\n":
    raise RuntimeError(f"unexpected final content: {final!r}")
if inode_before != inode_after:
    raise RuntimeError(f"inode changed: {inode_before} -> {inode_after}")

print(f"inode={inode_before} content_ok")
PY
)"
    local python_rc=$?

    if [ "$python_rc" -eq 0 ]; then
        record "PASS" "Open-handle rename" "$python_output"
    else
        record "FAIL" "Open-handle rename" "$(tr '\n' ' ' </tmp/guardfs-test-error)"
    fi

    if [ ! -e "$old_mount" ] && [ ! -e "$old_underlay" ]; then
        record "PASS" "Old paths" "removed"
    else
        record "FAIL" "Old paths" "still present"
    fi

    expected_content=$'before rename\nafter rename'
    mount_content="$(cat "$new_mount" 2>/tmp/guardfs-test-error)"
    underlay_content="$(cat "$new_underlay" 2>/tmp/guardfs-test-error)"
    check_equal "Mount renamed content" "$expected_content" "$mount_content"
    check_equal "Underlay renamed content" "$expected_content" "$underlay_content"
}

test_open_handle_unlink() {
    local file_name="open_unlink_$STAMP.txt"
    local mount_path="$MOUNT/$file_name"
    local underlay_path="$UNDERLAY/$file_name"
    local python_output

    ARTIFACT="none"
    export GUARDFS_TEST_MOUNT_FILE="$mount_path"
    export GUARDFS_TEST_UNDERLAY_FILE="$underlay_path"

    python_output="$(python3 - <<'PY' 2>/tmp/guardfs-test-error
import os

mount_path = os.environ["GUARDFS_TEST_MOUNT_FILE"]
underlay_path = os.environ["GUARDFS_TEST_UNDERLAY_FILE"]

with open(mount_path, "w+b") as handle:
    handle.write(b"before unlink\n")
    handle.flush()
    os.unlink(mount_path)
    if os.path.exists(mount_path) or os.path.exists(underlay_path):
        raise RuntimeError("pathname still exists after unlink")
    handle.seek(0)
    before = handle.read()
    handle.seek(0, os.SEEK_END)
    handle.write(b"after unlink\n")
    handle.flush()
    handle.seek(0)
    final = handle.read()

if before != b"before unlink\n":
    raise RuntimeError(f"unexpected content after unlink: {before!r}")
if final != b"before unlink\nafter unlink\n":
    raise RuntimeError(f"unexpected final fd content: {final!r}")
if os.path.exists(mount_path) or os.path.exists(underlay_path):
    raise RuntimeError("pathname reappeared after close")

print("open fd remained usable and paths stayed absent")
PY
)"
    local python_rc=$?

    if [ "$python_rc" -eq 0 ]; then
        record "PASS" "Open-handle unlink" "$python_output"
    else
        record "FAIL" "Open-handle unlink" "$(tr '\n' ' ' </tmp/guardfs-test-error)"
    fi

    if [ ! -e "$mount_path" ] && [ ! -e "$underlay_path" ]; then
        record "PASS" "Final pathname state" "absent on mount and underlay"
    else
        record "FAIL" "Final pathname state" "path remains"
        ARTIFACT="$mount_path"
    fi
}

test_truncate_ftruncate() {
    local file_name="truncate_test_$STAMP.txt"
    local mount_path="$MOUNT/$file_name"
    local underlay_path="$UNDERLAY/$file_name"
    local mount_size underlay_size python_output mount_content underlay_content

    ARTIFACT="$mount_path"

    if printf '0123456789abcdef' >"$mount_path" 2>/tmp/guardfs-test-error; then
        record "PASS" "Create source" "size=16"
    else
        record "FAIL" "Create source" "$(tr '\n' ' ' </tmp/guardfs-test-error)"
    fi

    if truncate -s 5 "$mount_path" 2>/tmp/guardfs-test-error; then
        record "PASS" "TRUNCATE" "requested size=5"
    else
        record "FAIL" "TRUNCATE" "$(tr '\n' ' ' </tmp/guardfs-test-error)"
    fi

    mount_size="$(stat -c '%s' "$mount_path" 2>/dev/null)"
    underlay_size="$(stat -c '%s' "$underlay_path" 2>/dev/null)"
    check_equal "Mount size after truncate" "5" "$mount_size"
    check_equal "Underlay size after truncate" "5" "$underlay_size"

    export GUARDFS_TEST_MOUNT_FILE="$mount_path"
    python_output="$(python3 - <<'PY' 2>/tmp/guardfs-test-error
import os

path = os.environ["GUARDFS_TEST_MOUNT_FILE"]
with open(path, "r+b") as handle:
    os.ftruncate(handle.fileno(), 2)
    size = os.fstat(handle.fileno()).st_size
if size != 2:
    raise RuntimeError(f"unexpected ftruncate size: {size}")
print("size=2")
PY
)"
    local python_rc=$?

    if [ "$python_rc" -eq 0 ]; then
        record "PASS" "FTRUNCATE" "$python_output"
    else
        record "FAIL" "FTRUNCATE" "$(tr '\n' ' ' </tmp/guardfs-test-error)"
    fi

    mount_size="$(stat -c '%s' "$mount_path" 2>/dev/null)"
    underlay_size="$(stat -c '%s' "$underlay_path" 2>/dev/null)"
    check_equal "Mount size after ftruncate" "2" "$mount_size"
    check_equal "Underlay size after ftruncate" "2" "$underlay_size"

    mount_content="$(cat "$mount_path" 2>/dev/null)"
    underlay_content="$(cat "$underlay_path" 2>/dev/null)"
    check_equal "Mount final content" "01" "$mount_content"
    check_equal "Underlay final content" "01" "$underlay_content"
}

print_results() {
    echo
    echo "============================================================"
    echo " GuardFS Passthrough Test $TEST_NO"
    echo "============================================================"
    printf '%s' "$RESULTS" |
        while IFS='|' read -r status name detail; do
            [ -z "$status" ] && continue
            printf '%-5s | %-27s | %s\n' "$status" "$name" "$detail"
        done
    echo "------------------------------------------------------------"
    echo "PASS=$PASS_COUNT FAIL=$FAIL_COUNT"
    if [ "$FAIL_COUNT" -eq 0 ]; then
        echo "FINAL RESULT: PASS"
    else
        echo "FINAL RESULT: FAIL"
        echo "GuardFS log: tail -n 100 /tmp/guardfs-terminal.log"
    fi
    echo "Retained artifact: $ARTIFACT"
    echo "============================================================"
}

case "$TEST_NO" in
    1|2|3|4|5|6|7)
        if precheck; then
            case "$TEST_NO" in
                1) test_mkdir_rmdir ;;
                2) test_create_write_read ;;
                3) test_rename_stat_read ;;
                4) test_rename_unlink ;;
                5) test_open_handle_rename ;;
                6) test_open_handle_unlink ;;
                7) test_truncate_ftruncate ;;
            esac
        fi
        final_health
        print_results
        ;;
    *)
        usage
        exit 2
        ;;
esac

[ "$FAIL_COUNT" -eq 0 ]
