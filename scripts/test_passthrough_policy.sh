#!/usr/bin/env bash

set -u

MOUNT="${MOUNT:-$HOME/guardfs_runtime/mount}"
UNDERLAY="${UNDERLAY:-$HOME/guardfs_runtime/underlay}"
TEST_NO="${1:-}"
STAMP="$(date +%Y%m%d_%H%M%S)"
RESULT_FILE="$(mktemp /tmp/guardfs-policy-result.XXXXXX)"

cleanup() {
    rm -f -- "$RESULT_FILE"
}

trap cleanup EXIT

usage() {
    echo "Usage: $0 <test-number>"
    echo
    echo "   1  MEDIUM small write buffering"
    echo "   2  MEDIUM new-file staging"
    echo "   3  MEDIUM large write"
    echo "   4  MEDIUM -> LOW buffer commit"
    echo "   5  MEDIUM -> HIGH buffer drop"
    echo "   6  HIGH write blocking"
    echo "   7  HIGH rename blocking"
    echo "   8  HIGH unlink blocking"
    echo "   9  HIGH truncate blocking"
    echo "  10  HIGH open(O_TRUNC) bypass check"
    echo "  11  HIGH mkdir/rmdir blocking"
}

record_shell() {
    printf '%s|%s|%s\n' "$1" "$2" "$3" >>"$RESULT_FILE"
}

if ! [[ "$TEST_NO" =~ ^([1-9]|10|11)$ ]]; then
    usage
    exit 2
fi

echo "Running GuardFS policy test $TEST_NO..."

if mountpoint -q "$MOUNT"; then
    record_shell "PASS" "Precheck mount" "connected"
else
    record_shell "FAIL" "Precheck mount" "disconnected"
fi

GUARDFS_PID="$(pgrep -f '[p]ython3 .*guardfs/fuse_fs/passthrough.py' | head -n 1)"
if [ -n "$GUARDFS_PID" ]; then
    record_shell "PASS" "Precheck process" "PID=$GUARDFS_PID"
else
    record_shell "FAIL" "Precheck process" "not running"
fi

if mountpoint -q "$MOUNT" && [ -n "$GUARDFS_PID" ]; then
    GUARDFS_POLICY_TEST="$TEST_NO" \
    GUARDFS_POLICY_STAMP="$STAMP" \
    GUARDFS_POLICY_MOUNT="$MOUNT" \
    GUARDFS_POLICY_UNDERLAY="$UNDERLAY" \
    python3 - <<'PY' >>"$RESULT_FILE" 2>&1
import os
import signal
import sys
import time
import errno
import traceback
from collections import defaultdict
from pathlib import Path


test_no = int(os.environ["GUARDFS_POLICY_TEST"])
stamp = os.environ["GUARDFS_POLICY_STAMP"]
mount = Path(os.environ["GUARDFS_POLICY_MOUNT"])
underlay = Path(os.environ["GUARDFS_POLICY_UNDERLAY"])
results = []


def record(status, name, detail):
    detail = str(detail).replace("|", "/").replace("\n", " ")
    results.append((status, name, detail))


def check(name, condition, detail_pass, detail_fail):
    record("PASS" if condition else "FAIL", name, detail_pass if condition else detail_fail)


def force_state(state):
    path = Path(f"/tmp/guardfs_state_{os.getpid()}")
    path.write_text(state, encoding="utf-8")
    return path


def start_resume_helper():
    """Resume this process if HIGH policy sends SIGSTOP."""
    parent_pid = os.getpid()
    helper_pid = os.fork()

    if helper_pid == 0:
        for _ in range(50):
            time.sleep(0.1)
            try:
                os.kill(parent_pid, signal.SIGCONT)
            except ProcessLookupError:
                break
        os._exit(0)

    return helper_pid


def stop_resume_helper(helper_pid):
    try:
        os.kill(helper_pid, signal.SIGTERM)
    except ProcessLookupError:
        pass

    try:
        os.waitpid(helper_pid, 0)
    except ChildProcessError:
        pass


def activate_high(trigger_mount, trigger_underlay):
    trigger_underlay.write_bytes(b"HIGH-TRIGGER-ORIGINAL\n")
    state_path = force_state("HIGH")
    helper_pid = start_resume_helper()

    with trigger_mount.open("r+b", buffering=0) as handle:
        written = handle.write(b"BLOCKED")

    check(
        "HIGH activation write",
        written == len(b"BLOCKED"),
        "request acknowledged",
        f"unexpected return={written}",
    )
    check(
        "HIGH activation preserved",
        trigger_underlay.read_bytes() == b"HIGH-TRIGGER-ORIGINAL\n",
        "underlay unchanged",
        "trigger write reached underlay",
    )
    return state_path, helper_pid


def test_medium_small_write():
    name = f"policy_medium_small_{stamp}.txt"
    mount_path = mount / name
    underlay_path = underlay / name
    original = b"ORIGINAL-MEDIUM\n"
    payload = b"BUFFERED"
    underlay_path.write_bytes(original)
    state_path = force_state("MEDIUM")

    try:
        with mount_path.open("r+b", buffering=0) as handle:
            written = handle.write(payload)
            during = underlay_path.read_bytes()

        after = underlay_path.read_bytes()
        check("Small write acknowledged", written == len(payload), "full length", f"written={written}")
        check("Buffered during write", during == original, "underlay unchanged", f"underlay={during!r}")
        check("Buffered after close", after == original, "underlay unchanged", f"underlay={after!r}")
    finally:
        state_path.unlink(missing_ok=True)


def test_medium_new_file_staging():
    name = f"policy_medium_create_{stamp}.txt"
    mount_path = mount / name
    underlay_path = underlay / name
    staging_dir = Path("/tmp/guardfs_staging")
    before = set(staging_dir.glob("fh_*")) if staging_dir.exists() else set()
    state_path = force_state("MEDIUM")

    try:
        with mount_path.open("w+b", buffering=0) as handle:
            written = handle.write(b"STAGED-DATA\n")
            absent_while_open = not underlay_path.exists()

        deadline = time.monotonic() + 2.0

        while time.monotonic() < deadline:
            after = set(staging_dir.glob("fh_*")) if staging_dir.exists() else set()

            if after == before:
                break

            time.sleep(0.05)

        after = set(staging_dir.glob("fh_*")) if staging_dir.exists() else set()
        check("Staged create acknowledged", written == 12, "full length", f"written={written}")
        check("Underlay absent while open", absent_while_open, "not created", "created too early")
        check("Underlay absent after close", not underlay_path.exists(), "not created", "unexpected target exists")
        check("Staging release cleanup", after == before, "no new staging file", f"new={after - before}")
    finally:
        state_path.unlink(missing_ok=True)


def test_medium_large_write():
    name = f"policy_medium_large_{stamp}.bin"
    mount_path = mount / name
    underlay_path = underlay / name
    original = b"O" * 1_100_000
    payload = b"X" * 1_100_000
    underlay_path.write_bytes(original)
    state_path = force_state("MEDIUM")

    try:
        with mount_path.open("r+b", buffering=0) as handle:
            written = handle.write(payload)

        actual = underlay_path.read_bytes()
        check("Large write acknowledged", written == len(payload), "full length", f"written={written}")
        check("Large write applied", actual == payload, "underlay updated", f"size={len(actual)}")
    finally:
        state_path.unlink(missing_ok=True)


def test_medium_commit():
    import trio
    from guardfs.stage2.policy.medium import commit_buffers, handle_write_medium

    class FakeOps:
        def __init__(self):
            self._write_buffer = defaultdict(list)
            self._write_count = defaultdict(int)
            self._staging_pid = defaultdict(list)

        async def trigger_high(self, pid, reason=""):
            raise RuntimeError(f"unexpected HIGH: {reason}")

    path = Path(f"/tmp/guardfs_policy_commit_{stamp}.txt")
    original = b"ORIGINAL\n"
    payload = b"COMMITTED"
    path.write_bytes(original)
    fd = os.open(path, os.O_RDWR)
    ops = FakeOps()

    async def scenario():
        written = await handle_write_medium(fd, 0, payload, str(path), 4242, ops)
        buffered = path.read_bytes() == original and bool(ops._write_buffer[4242])
        await commit_buffers(4242, ops)
        return written, buffered

    try:
        written, buffered = trio.run(scenario)
        check("MEDIUM buffer prepared", buffered, "original preserved", "write was not buffered")
        check("LOW commit acknowledged", written == len(payload), "full length", f"written={written}")
        check("LOW commit applied", path.read_bytes().startswith(payload), "buffer committed", f"content={path.read_bytes()!r}")
    finally:
        os.close(fd)
        path.unlink(missing_ok=True)


def test_medium_drop():
    import trio
    from guardfs.stage2.policy.medium import drop_buffers, handle_write_medium

    class FakeOps:
        def __init__(self):
            self._write_buffer = defaultdict(list)
            self._write_count = defaultdict(int)
            self._staging_pid = defaultdict(list)

        async def trigger_high(self, pid, reason=""):
            raise RuntimeError(f"unexpected HIGH: {reason}")

    path = Path(f"/tmp/guardfs_policy_drop_{stamp}.txt")
    original = b"ORIGINAL-PRESERVED\n"
    path.write_bytes(original)
    fd = os.open(path, os.O_RDWR)
    ops = FakeOps()

    async def scenario():
        await handle_write_medium(fd, 0, b"MALICIOUS", str(path), 4343, ops)
        buffered_before = bool(ops._write_buffer[4343])
        await drop_buffers(4343, ops)
        return buffered_before

    try:
        buffered_before = trio.run(scenario)
        check("MEDIUM buffer prepared", buffered_before, "buffer exists", "buffer missing")
        check("HIGH drop cleared buffer", not ops._write_buffer.get(4343), "buffer removed", "buffer remains")
        check("HIGH drop preserved original", path.read_bytes() == original, "original unchanged", f"content={path.read_bytes()!r}")
    finally:
        os.close(fd)
        path.unlink(missing_ok=True)


def test_high_write():
    name = f"policy_high_write_{stamp}.txt"
    target_mount = mount / name
    target_underlay = underlay / name
    state_path, helper_pid = activate_high(target_mount, target_underlay)

    try:
        check("HIGH write blocked", target_underlay.read_bytes() == b"HIGH-TRIGGER-ORIGINAL\n", "original preserved", "content changed")
    finally:
        state_path.unlink(missing_ok=True)
        stop_resume_helper(helper_pid)


def test_high_rename():
    old_name = f"policy_high_rename_{stamp}_old.txt"
    new_name = f"policy_high_rename_{stamp}_new.txt"
    old_mount = mount / old_name
    old_underlay = underlay / old_name
    new_mount = mount / new_name
    new_underlay = underlay / new_name
    old_underlay.write_bytes(b"RENAME-ORIGINAL\n")
    trigger_mount = mount / f"policy_high_trigger_{stamp}.txt"
    trigger_underlay = underlay / f"policy_high_trigger_{stamp}.txt"
    state_path, helper_pid = activate_high(trigger_mount, trigger_underlay)

    try:
        os.rename(old_mount, new_mount)
        check("HIGH rename source preserved", old_underlay.exists(), "old path exists", "old path missing")
        check("HIGH rename target blocked", not new_underlay.exists(), "new path absent", "new path exists")
    finally:
        state_path.unlink(missing_ok=True)
        stop_resume_helper(helper_pid)


def test_high_unlink():
    name = f"policy_high_unlink_{stamp}.txt"
    target_mount = mount / name
    target_underlay = underlay / name
    target_underlay.write_bytes(b"DELETE-ORIGINAL\n")
    trigger_mount = mount / f"policy_high_trigger_{stamp}.txt"
    trigger_underlay = underlay / f"policy_high_trigger_{stamp}.txt"
    state_path, helper_pid = activate_high(trigger_mount, trigger_underlay)

    try:
        os.unlink(target_mount)
        check("HIGH unlink blocked", target_underlay.exists(), "original exists", "original deleted")
    finally:
        state_path.unlink(missing_ok=True)
        stop_resume_helper(helper_pid)


def test_high_truncate():
    name = f"policy_high_truncate_{stamp}.txt"
    target_mount = mount / name
    target_underlay = underlay / name
    original = b"TRUNCATE-ORIGINAL\n"
    target_underlay.write_bytes(original)
    trigger_mount = mount / f"policy_high_trigger_{stamp}.txt"
    trigger_underlay = underlay / f"policy_high_trigger_{stamp}.txt"
    state_path, helper_pid = activate_high(trigger_mount, trigger_underlay)

    try:
        os.truncate(target_mount, 0)
        check("HIGH truncate blocked", target_underlay.read_bytes() == original, "original preserved", "size/content changed")
    finally:
        state_path.unlink(missing_ok=True)
        stop_resume_helper(helper_pid)


def test_high_open_trunc():
    name = f"policy_high_open_trunc_{stamp}.txt"
    target_mount = mount / name
    target_underlay = underlay / name
    original = b"OPEN-TRUNC-ORIGINAL\n"

    target_underlay.write_bytes(original)

    trigger_mount = mount / f"policy_high_trigger_{stamp}.txt"
    trigger_underlay = underlay / f"policy_high_trigger_{stamp}.txt"

    state_path, helper_pid = activate_high(
        trigger_mount,
        trigger_underlay,
    )

    try:
        try:
            fd = os.open(
                target_mount,
                os.O_WRONLY | os.O_TRUNC,
            )
        except PermissionError:
            open_blocked = True
        else:
            open_blocked = False
            os.close(fd)

        check(
            "HIGH open(O_TRUNC) rejected",
            open_blocked,
            "EACCES returned",
            "open unexpectedly succeeded",
        )

        check(
            "HIGH open(O_TRUNC) preserved",
            target_underlay.read_bytes() == original,
            "original preserved",
            "bypass truncated original",
        )
    finally:
        state_path.unlink(missing_ok=True)
        stop_resume_helper(helper_pid)


def test_high_directories():
    new_name = f"policy_high_mkdir_{stamp}"
    old_name = f"policy_high_rmdir_{stamp}"
    new_mount = mount / new_name
    new_underlay = underlay / new_name
    old_mount = mount / old_name
    old_underlay = underlay / old_name
    old_underlay.mkdir()
    trigger_mount = mount / f"policy_high_trigger_{stamp}.txt"
    trigger_underlay = underlay / f"policy_high_trigger_{stamp}.txt"
    state_path, helper_pid = activate_high(trigger_mount, trigger_underlay)

    try:
        try:
            os.mkdir(new_mount)
        except OSError as exc:
            mkdir_blocked = exc.errno == errno.EACCES
            mkdir_detail = f"errno={exc.errno}"
        else:
            mkdir_blocked = False
            mkdir_detail = "mkdir unexpectedly succeeded"

        check(
            "HIGH mkdir rejected",
            mkdir_blocked,
            mkdir_detail,
            mkdir_detail,
        )

        check(
            "HIGH mkdir blocked",
            not new_underlay.exists(),
            "new directory absent",
            "bypass created directory",
        )

        try:
            os.rmdir(old_mount)
        except OSError as exc:
            rmdir_blocked = exc.errno == errno.EACCES
            rmdir_detail = f"errno={exc.errno}"
        else:
            rmdir_blocked = False
            rmdir_detail = "rmdir unexpectedly succeeded"

        check(
            "HIGH rmdir rejected",
            rmdir_blocked,
            rmdir_detail,
            rmdir_detail,
        )

        check(
            "HIGH rmdir blocked",
            old_underlay.exists(),
            "old directory preserved",
            "bypass removed directory",
        )
    finally:
        state_path.unlink(missing_ok=True)
        stop_resume_helper(helper_pid)


tests = {
    1: test_medium_small_write,
    2: test_medium_new_file_staging,
    3: test_medium_large_write,
    4: test_medium_commit,
    5: test_medium_drop,
    6: test_high_write,
    7: test_high_rename,
    8: test_high_unlink,
    9: test_high_truncate,
    10: test_high_open_trunc,
    11: test_high_directories,
}

try:
    tests[test_no]()
except BaseException as exc:
    record("FAIL", "Unhandled test exception", f"{type(exc).__name__}: {exc}")
finally:
    for status, name, detail in results:
        print(f"{status}|{name}|{detail}")

sys.exit(1 if any(status == "FAIL" for status, _, _ in results) else 0)
PY
    PYTHON_RC=$?

    if [ "$PYTHON_RC" -ne 0 ] && ! grep -q '^FAIL|' "$RESULT_FILE"; then
        record_shell "FAIL" "Policy runner" "python exit=$PYTHON_RC"
    fi
fi

if mountpoint -q "$MOUNT"; then
    record_shell "PASS" "Final mount health" "connected"
else
    record_shell "FAIL" "Final mount health" "disconnected"
fi

FINAL_PID="$(pgrep -f '[p]ython3 .*guardfs/fuse_fs/passthrough.py' | head -n 1)"
if [ -n "$FINAL_PID" ]; then
    record_shell "PASS" "Final process health" "PID=$FINAL_PID"
else
    record_shell "FAIL" "Final process health" "not running"
fi

PASS_COUNT="$(grep -c '^PASS|' "$RESULT_FILE" || true)"
FAIL_COUNT="$(grep -c '^FAIL|' "$RESULT_FILE" || true)"

echo
echo "============================================================"
echo " GuardFS Policy Test $TEST_NO"
echo "============================================================"
while IFS='|' read -r status name detail; do
    if [ "$status" = "PASS" ] || [ "$status" = "FAIL" ]; then
        printf '%-5s | %-31s | %s\n' "$status" "$name" "$detail"
    fi
done <"$RESULT_FILE"
echo "------------------------------------------------------------"
echo "PASS=$PASS_COUNT FAIL=$FAIL_COUNT"

if [ "$FAIL_COUNT" -eq 0 ]; then
    echo "FINAL RESULT: PASS"
else
    echo "FINAL RESULT: FAIL"
    echo "GuardFS log: tail -n 150 /tmp/guardfs-terminal.log"
fi

if [ "$TEST_NO" = "4" ] || [ "$TEST_NO" = "5" ]; then
    echo "NOTE: this test directly verifies commit/drop policy functions."
    echo "      Forced MEDIUM state alone does not register Stage2 reevaluation."
fi
echo "============================================================"

[ "$FAIL_COUNT" -eq 0 ]
