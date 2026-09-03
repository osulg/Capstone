import os
import signal
import time

from guardfs.common.paths import FILESECURITY_LOG_PATH

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
    log_path = FILESECURITY_LOG_PATH
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
    - MEDIUM 단계에서 보관 중이던 write buffer 폐기 (전역 버퍼 카운트 반영,
      스테이징으로 옮겨뒀던 unlink 복원까지 medium.drop_buffers()가 전담)
    - HIGH 진입 사유 저장
    - 이미 Stage2 큐에 들어간 pid 해제

    trigger_high()가 호출되는 경로가 여러 곳(write 중 즉시 격상, reeval 중
    격상 등)이라 정리 로직을 여기 한 곳(medium.drop_buffers)으로 모아서
    중복·누락 없이 항상 같은 방식으로 정리되게 한다.
    """
    from guardfs.stage2.policy.medium import drop_buffers

    await drop_buffers(pid, ops)
    ops._high_reason[pid] = reason or "High-risk process detected"
    ops._queued_stage2.discard(pid)

    print(
        f"[HIGH] pid={pid} 진입 정리 완료 (reason={ops._high_reason[pid]})"
    )


async def handle_open_trunc_high(
    path: str,
    flags: int,
    pid: int,
    ops,
) -> None:
    process = get_process_name(pid)
    reason = ops._high_reason.get(
        pid,
        "High-risk process detected",
    )

    log_high_event(
        pid=pid,
        process=process,
        path=path,
        action="OPEN(O_TRUNC)",
        result="BLOCKED",
        reason=reason,
    )

    suspend_process_once(pid, ops)

    print(
        f"[HIGH] pid={pid} path={path} "
        f"open(O_TRUNC) 차단 flags={flags}"
    )


async def handle_mkdir_high(
    path: str,
    pid: int,
    ops,
) -> None:
    process = get_process_name(pid)
    reason = ops._high_reason.get(
        pid,
        "High-risk process detected",
    )

    log_high_event(
        pid=pid,
        process=process,
        path=path,
        action="MKDIR",
        result="BLOCKED",
        reason=reason,
    )

    suspend_process_once(pid, ops)

    print(f"[HIGH] pid={pid} path={path} mkdir 차단")


async def handle_rmdir_high(
    path: str,
    pid: int,
    ops,
) -> None:
    process = get_process_name(pid)
    reason = ops._high_reason.get(
        pid,
        "High-risk process detected",
    )

    log_high_event(
        pid=pid,
        process=process,
        path=path,
        action="RMDIR",
        result="BLOCKED",
        reason=reason,
    )

    suspend_process_once(pid, ops)

    print(f"[HIGH] pid={pid} path={path} rmdir 차단")
