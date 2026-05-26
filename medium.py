# medium.py
import os
import time
import trio
from states import ProcState


def log_medium_event(pid: int, path: str, action: str, result: str, reason: str = "") -> None:
    log_path = os.path.expanduser("~/filesecurity.log")
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    log_msg = (
        "[MEDIUM]\n"
        f"Time: {now}\n"
        f"PID: {pid}\n"
        f"Target: {path}\n"
        f"Action: {action}\n"
        f"Result: {result}\n"
        f"Reason: {reason}\n"
        "\n"
    )
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(log_msg)

MAGIC_BYTES = {
    ".pdf":  b"%PDF-",
    ".docx": b"PK",
    ".xlsx": b"PK",
    ".pptx": b"PK",
    ".jpg":  b"\xff\xd8\xff",
    ".png":  b"\x89PNG",
    ".zip":  b"PK",
}

WRITE_DELAY_MID  = 0.1
WRITE_DELAY_HIGH = 0.5
WRITE_TH_MID     = 10
WRITE_TH_HIGH    = 20
SIZE_LIMIT       = 1_000_000


def validate_magic(path: str, buf: bytes, off: int) -> bool:
    if off != 0:
        return True
    ext = os.path.splitext(path)[1].lower()
    magic = MAGIC_BYTES.get(ext)
    if magic is None:
        return True
    return buf[:len(magic)] == magic


async def handle_write_medium(
    fd: int,
    off: int,
    buf: bytes,
    path: str,
    pid: int,
    ops,
) -> int:
    file_size = len(buf)

    if file_size < SIZE_LIMIT:
        if not validate_magic(path, buf, off):
            print(f"[MEDIUM] pid={pid} path={path} magic number 불일치 → High 격상")
            log_medium_event(pid, path, "WRITE", "ESCALATED_TO_HIGH", "magic number 불일치")
            await ops.trigger_high(pid, reason="magic_mismatch")
            return len(buf)

        ops._write_buffer[pid].append((fd, off, buf, path))
        print(f"[MEDIUM] pid={pid} path={path} off={off} size={file_size} → 버퍼 보관")
        log_medium_event(pid, path, "WRITE", "BUFFERED", f"size={file_size}")

    else:
        print(f"[MEDIUM] pid={pid} path={path} size={file_size} → 대용량 MTD_DELAY")
        try:
            os.pwrite(fd, buf, off)
        except OSError:
            pass

    count = ops._write_count[pid] + 1
    ops._write_count[pid] = count

    if count > WRITE_TH_HIGH:
        await trio.sleep(WRITE_DELAY_HIGH)
    elif count > WRITE_TH_MID:
        await trio.sleep(WRITE_DELAY_MID)

    return len(buf)


async def commit_buffers(pid: int, ops) -> None:
    buffers = ops._write_buffer.pop(pid, [])

    for (fd, off, buf, path) in buffers:
        if not validate_magic(path, buf, off):
            print(f"[COMMIT] pid={pid} path={path} 구조 깨짐 → 커밋 취소")
            await ops.trigger_high(pid, reason="magic_mismatch_on_commit")
            return

        try:
            # fd 대신 path로 직접 열어서 씀
            with open(path, "r+b") as f:
                f.seek(off)
                f.write(buf)
            print(f"[COMMIT] pid={pid} path={path} off={off} → 커밋 완료")
            log_medium_event(pid, path, "COMMIT", "SUCCESS", "정상 판정 후 LOW 복귀")
        except FileNotFoundError:
            with open(path, "wb") as f:
                f.seek(off)
                f.write(buf)
            print(f"[COMMIT] pid={pid} path={path} off={off} → 새 파일 커밋 완료")
            log_medium_event(pid, path, "COMMIT", "SUCCESS", "새 파일 생성 후 커밋")
        except OSError as e:
            print(f"[COMMIT] pid={pid} path={path} 오류: {e}")
            log_medium_event(pid, path, "COMMIT", "FAILED", str(e))

    ops._write_count.pop(pid, None)

    for staging_path in ops._staging_pid.pop(pid, []):
        try:
            os.unlink(staging_path)
        except OSError:
            pass


async def drop_buffers(pid: int, ops) -> None:
    dropped = ops._write_buffer.pop(pid, [])
    ops._write_count.pop(pid, None)

    for staging_path in ops._staging_pid.pop(pid, []):
        try:
            os.unlink(staging_path)
        except OSError:
            pass

    print(f"[DROP] pid={pid} 버퍼 {len(dropped)}개 드롭 → 원본 보존")
    log_medium_event(pid, "", "DROP", "BUFFER_DROPPED", f"버퍼 {len(dropped)}개 드롭, 원본 보존")


async def validate_medium_buffers(pid: int, ops) -> bool:
    for (fd, off, buf, path) in ops._write_buffer.get(pid, []):
        if not validate_magic(path, buf, off):
            print(f"[VALIDATE] pid={pid} path={path} 구조 깨짐 감지")
            return True
    return False