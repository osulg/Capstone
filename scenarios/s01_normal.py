"""S01: normal file lifecycle through an existing HoldFS mount.

Run from the repository root: python3 -m scenarios.s01_normal
Only the mount is modified; the underlay is read for verification.

*실행
python3 -m scenarios.s01_normal

*실행 - 결과저장
python3 -m scenarios.s01_normal > /tmp/s01-result.json
"""

import argparse
import hashlib
import json
import math
import os
import stat
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

CONTENT = b"hello holdfs\nnormal document editing test\n"


def timestamp():
    return datetime.now(UTC).isoformat()


def wait_until(probe, health, timeout, interval=0.2):
    """Retry pending state only; permission/disconnection errors propagate."""
    started = time.monotonic()
    deadline = started + timeout
    while True:
        health()
        if probe():
            return time.monotonic() - started
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(f"Propagation not confirmed within {timeout:.1f}s")
        time.sleep(min(interval, remaining))


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def absent(path):
    # Unlike exists(), only ENOENT means absence; disconnected FUSE must fail.
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    return False


def check_health(mount, guardfs_pid):
    require(sys.platform == "linux", "Run this scenario on Linux with HoldFS.")
    require(os.path.ismount(mount), "HoldFS mount is not mounted.")
    # stat also detects a disconnected userspace filesystem.
    mount.stat()
    cmdline = Path(f"/proc/{guardfs_pid}/cmdline").read_bytes()
    require(
        b"guardfs" in cmdline and b"python" in cmdline,
        "The supplied PID is not a running HoldFS Python process.",
    )


def find_guardfs_pid():
    candidates = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            command = (entry / "cmdline").read_bytes()
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        if b"python" in command and (
            b"guardfs/fuse_fs/passthrough.py" in command
            or b"guardfs.main" in command
            or b"guardfs/main.py" in command
        ):
            candidates.append(int(entry.name))
    require(
        len(candidates) == 1, "Use --holdfs-pid: cannot identify one HoldFS process."
    )
    return candidates[0]


def run(
    mount,
    underlay,
    guardfs_pid=None,
    on_step=None,
    propagation_timeout=30.0,
    total_timeout=120.0,
    on_progress=None,
):
    """Return a JSON-compatible report; stop on first failed operation.

    Failed runs retain their unique directory for diagnosis. No recursive cleanup
    or forced state overrides are used. on_step receives completed step records.
    on_progress receives running and completed records immediately, in order.
    """
    if not all(
        math.isfinite(value) and value > 0
        for value in (propagation_timeout, total_timeout)
    ):
        raise ValueError("Timeouts must be positive and finite.")
    deadline = time.monotonic() + total_timeout
    mount = Path(os.path.abspath(Path(mount).expanduser()))
    underlay = Path(underlay).expanduser().resolve()
    run_id = "s01_" + uuid.uuid4().hex
    folder = mount / run_id
    original = folder / "test.txt"
    renamed = folder / "test_renamed.txt"
    child = folder / "test_dir"
    report = {
        "scenario_id": "S01",
        "run_id": run_id,
        "pid": os.getpid(),
        "guardfs_pid": guardfs_pid,
        "holdfs_pid": guardfs_pid,
        "started_at": timestamp(),
        "mount": str(mount),
        "underlay": str(underlay),
        "artifact_path": str(folder),
        "steps": [],
        "status": "running",
        "detection_verification": "not_checked",
        "propagation_timeout_seconds": propagation_timeout,
        "total_timeout_seconds": total_timeout,
    }
    step_wait_seconds = 0.0

    def under(path):
        return underlay / path.relative_to(mount)

    def wait(probe):
        nonlocal step_wait_seconds
        remaining = deadline - time.monotonic()
        require(remaining > 0, "Scenario total timeout exceeded.")
        started = time.monotonic()
        try:
            wait_until(
                probe,
                lambda: check_health(mount, guardfs_pid),
                min(propagation_timeout, remaining),
            )
        finally:
            step_wait_seconds += time.monotonic() - started

    def same_file(path, expected):
        def ready():
            for target in (path, under(path)):
                try:
                    require(
                        stat.S_ISREG(target.stat().st_mode), f"Not a file: {target}"
                    )
                    if target.read_bytes() != expected:
                        return False
                except FileNotFoundError:
                    return False
            return True

        wait(ready)
        return {"sha256": hashlib.sha256(expected).hexdigest(), "bytes": len(expected)}

    def directories(path):
        def ready():
            for target in (path, under(path)):
                try:
                    require(
                        stat.S_ISDIR(target.stat().st_mode),
                        f"Not a directory: {target}",
                    )
                except FileNotFoundError:
                    return False
            return True

        wait(ready)

    def missing(path):
        wait(lambda: absent(path) and absent(under(path)))

    def precheck():
        nonlocal guardfs_pid
        require(sys.platform == "linux", "Run this scenario on Linux with HoldFS.")
        require(mount != underlay, "Mount and underlay must be different paths.")
        require(underlay.is_dir(), "Underlay directory is missing.")
        guardfs_pid = guardfs_pid or find_guardfs_pid()
        report["guardfs_pid"] = guardfs_pid
        report["holdfs_pid"] = guardfs_pid
        check_health(mount, guardfs_pid)
        require(
            absent(folder) and absent(under(folder)), "Run directory already exists."
        )

    def prepare():
        folder.mkdir()
        directories(folder)

    def create():
        with original.open("xb"):
            pass
        return same_file(original, b"")

    def write():
        with original.open("r+b") as handle:
            handle.write(CONTENT)
            handle.flush()
        return same_file(original, CONTENT)

    def mkdir():
        child.mkdir()
        directories(child)

    def rename():
        before = (original.stat().st_ino, under(original).stat().st_ino)
        original.rename(renamed)
        missing(original)
        details = same_file(renamed, CONTENT)
        after = (renamed.stat().st_ino, under(renamed).stat().st_ino)
        require(before == after, "Inode changed after rename.")
        return details

    def unlink():
        renamed.unlink()
        missing(renamed)

    def rmdir():
        child.rmdir()
        missing(child)
        folder.rmdir()
        missing(folder)

    operations = [
        ("PRECHECK", precheck),
        ("PREPARE", prepare),
        ("CREATE", create),
        ("WRITE", write),
        ("READ", lambda: same_file(original, CONTENT)),
        ("MKDIR", mkdir),
        ("RENAME", rename),
        ("READ_AFTER_RENAME", lambda: same_file(renamed, CONTENT)),
        ("UNLINK", unlink),
        ("RMDIR", rmdir),
    ]
    for name, operation in operations:
        step_wait_seconds = 0.0
        step = {
            "name": name,
            "status": "running",
            "started_at": timestamp(),
        }

        # 실제 작업 전에 시작을 알린다. 최종 보고서에는 아직 추가하지 않는다.
        if on_progress:
            on_progress(dict(step))

        try:
            require(
                time.monotonic() < deadline,
                "Scenario total timeout exceeded.",
            )
            details = operation()
            check_health(mount, guardfs_pid)
            step.update(status="passed", details=details or {})

        except (OSError, RuntimeError) as error:
            step.update(status="failed", error=str(error))

        step["finished_at"] = timestamp()
        step["propagation_wait_seconds"] = round(step_wait_seconds, 3)

        # 완료 또는 실패를 즉시 알리고, 최종 보고서에도 동일한 결과를 보관한다.
        report["steps"].append(dict(step))
        if on_progress:
            on_progress(dict(step))

        # 기존 호출자는 완료 이벤트만 받도록 호환성을 유지한다.
        if on_step:
            on_step(dict(step))

        if step["status"] == "failed":
            report["status"] = "failed"
            break
    else:
        report["status"] = "passed"
        report["artifact_path"] = None

    report["finished_at"] = timestamp()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    runtime = Path.home() / "guardfs_runtime"
    parser.add_argument("--mount", type=Path, default=runtime / "mount")
    parser.add_argument("--underlay", type=Path, default=runtime / "underlay")
    parser.add_argument("--holdfs-pid", "--guardfs-pid", dest="holdfs_pid", type=int)
    parser.add_argument("--propagation-timeout", type=float, default=30.0)
    parser.add_argument("--total-timeout", type=float, default=120.0)
    args = parser.parse_args()

    def progress(step):
        event = {
            "type": "step",
            "scenario_id": "S01",
            "pid": os.getpid(),
            "step": step,
        }

        # stderr: 한 줄에 하나의 진행 이벤트. stdout의 최종 JSON과 분리한다.
        print(
            "PROGRESS " + json.dumps(event, ensure_ascii=False),
            file=sys.stderr,
            flush=True,
        )

    try:
        report = run(
            mount=args.mount,
            underlay=args.underlay,
            guardfs_pid=args.holdfs_pid,
            propagation_timeout=args.propagation_timeout,
            total_timeout=args.total_timeout,
            on_progress=progress,
        )

    except ValueError as error:
        parser.error(str(error))

    # stdout에는 최종 결과 JSON만 출력한다.
    print(
        json.dumps(report, ensure_ascii=False, indent=2),
        flush=True,
    )

    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
