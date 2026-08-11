# low.py
import os

async def handle_write_low(
    fd: int,
    off: int,
    buf: bytes,
    path: str,
    pid: int,
    ops,
) -> int:
    """
    LOW 상태 write 처리.
    - 즉시 디스크에 기록 (버퍼링 없음)
    """
    try:
        if hasattr(os, "pwrite"):
            n = os.pwrite(fd, buf, off)
        else:
            os.lseek(fd, off, os.SEEK_SET)
            n = os.write(fd, buf)
        return n
    except OSError as e:
        import errno
        import pyfuse3
        raise pyfuse3.FUSEError(e.errno)

async def handle_low_return(pid: int, ops) -> None:
    """
    MEDIUM → LOW 복귀 시 정리 작업.
    - _queued_stage2 에서 pid 제거 → 이후 재탐지 가능
    - _write_count 초기화 → 다음 MEDIUM 진입 시 딜레이 계산 오류 방지
    """
    ops._queued_stage2.discard(pid)
    ops._write_count.pop(pid, None)
    print(f"[LOW] pid={pid} 복귀 정리 완료 (queued_stage2 해제, write_count 초기화)")