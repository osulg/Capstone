import os
import signal
import time

def get_process_name(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/comm", "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return "unknown"


def log_high_event(
    pid: int,
    process: str,
    path: str,
    action: str,
    result: str,
    reason: str,
) -> None:
    log_path = os.path.expanduser("~/filesecurity.log")
    now = time.strftime("%Y-%m-%d %H:%M:%S")

    log_msg = (
        "[HIGH]\n"
        f"Time: {now}\n"
        f"PID: {pid}\n"
        f"Process: {process}\n"
        f"Target: {path}\n"
        f"Action: {action}\n"
        f"Result: {result}\n"
        f"Reason: {reason}\n"
        "\n"
    )

    with open(log_path, "a", encoding="utf-8") as f:
        f.write(log_msg)

    print(log_msg)


def suspend_process_once(pid: int, ops) -> None:
    if pid in ops._suspended_pids:
        print(f"[HIGH] pid={pid} 이미 suspend 상태")
        return

    try:
        os.kill(pid, signal.SIGSTOP)
        ops._suspended_pids.add(pid)
        print(f"[HIGH] pid={pid} suspend 완료")
    except ProcessLookupError:
        print(f"[HIGH] pid={pid} 프로세스 없음")
    except PermissionError:
        print(f"[HIGH] pid={pid} suspend 권한 없음")


async def handle_write_high(
    fd: int,
    off: int,
    buf: bytes,
    path: str,
    pid: int,
    ops,
) -> int:
    process = get_process_name(pid)
    reason = ops._high_reason.get(pid, "High-risk process detected")

    log_high_event(
        pid=pid,
        process=process,
        path=path,
        action="WRITE",
        result="BLOCKED",
        reason=reason,
    )

    suspend_process_once(pid, ops)

    # 실제 디스크에는 기록하지 않음
    return len(buf)


async def handle_unlink_high(
    path: str,
    pid: int,
    ops,
) -> None:
    process = get_process_name(pid)
    reason = ops._high_reason.get(pid, "High-risk process detected")

    log_high_event(
        pid=pid,
        process=process,
        path=path,
        action="DELETE",
        result="BLOCKED",
        reason=reason,
    )

    suspend_process_once(pid, ops)

    print(f"[HIGH] pid={pid} path={path} 삭제 차단")


async def handle_rename_high(
    old_path: str,
    new_path: str,
    pid: int,
    ops,
) -> None:
    process = get_process_name(pid)
    reason = ops._high_reason.get(pid, "High-risk process detected")

    log_high_event(
        pid=pid,
        process=process,
        path=f"{old_path} -> {new_path}",
        action="RENAME",
        result="BLOCKED",
        reason=reason,
    )

    suspend_process_once(pid, ops)

    print(f"[HIGH] pid={pid} rename 차단: {old_path} -> {new_path}")


async def handle_truncate_high(
    path: str,
    size: int,
    pid: int,
    ops,
) -> None:
    process = get_process_name(pid)
    reason = ops._high_reason.get(pid, "High-risk process detected")

    log_high_event(
        pid=pid,
        process=process,
        path=path,
        action=f"TRUNCATE(size={size})",
        result="BLOCKED",
        reason=reason,
    )

    suspend_process_once(pid, ops)

    print(f"[HIGH] pid={pid} path={path} truncate 차단")


async def handle_high_enter(pid: int, ops, reason: str = "") -> None:
    """
    HIGH 진입 시 정리 작업.
    - MEDIUM 단계에서 보관 중이던 write buffer 폐기
    - write_count 초기화
    - HIGH 진입 사유 저장
    - 이미 Stage2 큐에 들어간 pid 해제
    """
    dropped = ops._write_buffer.pop(pid, [])
    ops._write_count.pop(pid, None)
    ops._high_reason[pid] = reason or "High-risk process detected"
    ops._queued_stage2.discard(pid)

    print(
        f"[HIGH] pid={pid} 진입 정리 완료 "
        f"(buffer {len(dropped)}개 드롭, write_count 초기화, reason={ops._high_reason[pid]})"
    )