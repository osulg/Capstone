"""정책 차단으로 정지된 공격 자식을 확인하고 회수한다."""

import os
import posixpath
import subprocess
import time
from pathlib import Path

from guardfs.common.paths import FILESECURITY_LOG_PATH


class PolicyBlockedError(RuntimeError):
    def __init__(self, evidence):
        super().__init__("HoldFS 정책 차단을 확인해 공격 프로세스를 종료·회수했습니다.")
        self.evidence = evidence


def capture_policy_position():
    """공격 시작 전 로그 위치를 기록해 이전 실행의 근거를 제외한다."""
    try:
        with Path(FILESECURITY_LOG_PATH).open("rb") as stream:
            info = os.fstat(stream.fileno())
            offset = info.st_size
            stream.seek(max(0, offset - 64))
            anchor = stream.read()
            return info.st_dev, info.st_ino, offset, anchor
    except OSError:
        # 근거 조회 불가 시 조기 차단 판정을 하지 않고 기존 제한을 적용한다.
        return None


def stopped_process_matches(pid, start_time_ticks):
    if start_time_ticks is None:
        return False

    try:
        text = Path(f"/proc/{pid}/stat").read_text()
        fields = text.rsplit(")", 1)[1].split()

        # /proc stat의 상태는 3번, 시작 시각은 22번 필드다.
        return fields[0] == "T" and int(fields[19]) == start_time_ticks
    except (OSError, ValueError, IndexError):
        return False


def find_blocking_event(checkpoint, pid, workspace):
    if checkpoint is None:
        return None

    device, inode, offset, anchor = checkpoint
    root = posixpath.normpath(str(workspace))

    try:
        with Path(FILESECURITY_LOG_PATH).open("rb") as stream:
            info = os.fstat(stream.fileno())

            if (
                (info.st_dev, info.st_ino) != (device, inode)
                or info.st_size < offset
                or info.st_size - offset > 4 * 1024 * 1024
            ):
                return None

            stream.seek(offset - len(anchor))
            if stream.read(len(anchor)) != anchor:
                return None

            stream.seek(offset)
            text = stream.read(4 * 1024 * 1024).decode("utf-8")

    except (OSError, UnicodeDecodeError):
        return None

    for block in text.replace("\r\n", "\n").split("\n\n")[:-1]:
        lines = block.splitlines()
        if not lines or lines[0] != "[HIGH]":
            continue

        fields = {}
        for line in lines[1:]:
            key, separator, value = line.partition(": ")
            if separator:
                fields[key] = value

        if (
            fields.get("PID") != str(pid)
            or fields.get("Result") != "BLOCKED"
            or fields.get("Action") not in ("WRITE", "RENAME", "TRUNCATE")
        ):
            continue

        paths = fields.get("Target", "").split(" -> ")
        if not paths or not all(
            posixpath.isabs(path)
            and posixpath.commonpath((root, posixpath.normpath(path))) == root
            for path in paths
        ):
            continue

        return {
            "source": "policy",
            "level": "HIGH",
            "pid": pid,
            "op": fields["Action"],
            "result": "BLOCKED",
            "path": fields["Target"],
            "reason": fields.get("Reason", ""),
            "logged_at": fields.get("Time"),
        }

    return None


def communicate_with_policy_watch(
    process,
    metadata,
    *,
    timeout,
    checkpoint,
    workspace,
):
    deadline = time.monotonic() + timeout

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(process.args, timeout)

        try:
            return process.communicate(timeout=min(0.2, remaining))
        except subprocess.TimeoutExpired:
            pass

        if not stopped_process_matches(
            process.pid,
            metadata.get("start_time_ticks"),
        ):
            continue

        event = find_blocking_event(
            checkpoint,
            process.pid,
            workspace,
        )
        if event is None:
            continue

        process.kill()
        process.communicate(timeout=3.0)

        raise PolicyBlockedError(
            {
                "confirmed": True,
                "process_reaped": process.returncode is not None,
                "pid": process.pid,
                "start_time_ticks": metadata["start_time_ticks"],
                "returncode": process.returncode,
                "event": event,
            }
        )
