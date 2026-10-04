# medium.py
import io
import os
import time
import zipfile

import trio

from guardfs.common.paths import FILESECURITY_LOG_PATH
from guardfs.common.config import (
    ENTROPY_HEADER_SIZE,
    MEDIUM_SIZE_LIMIT,
    EXTENSION_GROUPS,
    MEDIUM_DELAY_PHASES,
    MEDIUM_GLOBAL_BUFFER_LIMIT_BYTES,
)
from guardfs.stage1.entropy import shannon_entropy


def log_medium_event(pid: int, path: str, action: str, result: str, reason: str = "") -> None:
    log_path = FILESECURITY_LOG_PATH
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


def validate_magic(path: str, buf: bytes, off: int) -> bool:
    if off != 0:
        return True
    ext = os.path.splitext(path)[1].lower()
    magic = MAGIC_BYTES.get(ext)
    if magic is None:
        return True
    return buf[:len(magic)] == magic


# ========== 규칙 1: 확장자 그룹 분류 ========== #
_EXT_TO_GROUP = {
    ext: group
    for group, cfg in EXTENSION_GROUPS.items()
    for ext in cfg["exts"]
}


def classify_extension(path: str) -> str:
    """EXTENSION_GROUPS 어디에도 없으면 가장 보수적인 UNKNOWN으로 취급한다."""
    ext = os.path.splitext(path)[1].lower()
    return _EXT_TO_GROUP.get(ext, "UNKNOWN")


# ========== 규칙 2: magic byte를 넘어선 내부 구조 검증 ========== #
def structural_check(path: str, data: bytes) -> bool:
    """
    커밋 직전, 재구성된 파일 전체(data)를 대상으로 내부 구조 일관성을 검증한다.
    magic byte만 맞춰서 회피하는 경우(예: PK 헤더만 두고 내부 XML을 깨뜨림)를
    잡기 위한 것으로, HIGH_VALUE 그룹에만 적용한다.
    True = 정상, False = 구조 파괴 → HIGH 격상 대상.
    """
    ext = os.path.splitext(path)[1].lower()

    if ext == ".pdf":
        return data[:5] == b"%PDF-" and b"%%EOF" in data[-1024:]

    if ext in {".docx", ".xlsx", ".pptx"}:
        if data[:2] != b"PK":
            return False
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
            return "[Content_Types].xml" in z.namelist()
        except Exception:
            return False  # ZIP 파싱 실패 = 구조 파괴

    if ext in {".db", ".sqlite"}:
        return data[:16] == b"SQLite format 3\x00"

    # .sql/.mdb/.kdbx/.key/.pem/.wallet 등은 표준화된 내부 구조 검사기가 없어
    # magic byte(또는 확장자 자체) 검증만으로 충분하다고 보고 통과시킨다.
    return True


def _reconstruct_final_content(path: str, ordered_writes: list, truncated: bool) -> bytes:
    """
    한 경로에 대해 버퍼된 (off, buf)들을 순서대로 적용한 최종 바이트를
    메모리에서 재구성한다. O_TRUNC로 열렸던 경우 원본을 무시하고 빈
    상태에서 시작하고, 아니면 디스크에 남아있는 원본 위에 얹는다.
    """
    if truncated or not os.path.exists(path):
        data = bytearray()
    else:
        try:
            with open(path, "rb") as f:
                data = bytearray(f.read())
        except OSError:
            data = bytearray()

    for off, buf in ordered_writes:
        end = off + len(buf)
        if end > len(data):
            data.extend(b"\x00" * (end - len(data)))
        data[off:end] = buf

    return bytes(data)


def _phase_delay_ms(elapsed_sec: float, trusted: bool) -> int:
    for phase_end, untrusted_ms, trusted_ms in MEDIUM_DELAY_PHASES:
        if elapsed_sec < phase_end:
            return trusted_ms if trusted else untrusted_ms
    return MEDIUM_DELAY_PHASES[-1][2 if trusted else 1]


async def handle_write_medium(
    fd: int,
    off: int,
    buf: bytes,
    path: str,
    pid: int,
    ops,
) -> int:
    try:
        on_disk_size = os.fstat(fd).st_size
    except OSError:
        on_disk_size = 0

    file_size = max(on_disk_size, off + len(buf))
    trusted = ops.is_trusted_process(pid)
    group_name = classify_extension(path)
    group = EXTENSION_GROUPS[group_name]

    if pid not in ops._medium_entered_at:
        ops._medium_entered_at[pid] = trio.current_time()

    # 비신뢰 경로(/tmp, 다운로드 등)는 파일 크기와 무관하게 항상 버퍼링을 시도한다.
    # 신뢰 경로는 기존과 동일하게 크기 기준으로만 분기한다.
    if (not trusted) or file_size < MEDIUM_SIZE_LIMIT:
        if not validate_magic(path, buf, off):
            print(f"[MEDIUM] pid={pid} path={path} magic number 불일치 → High 격상")
            log_medium_event(pid, path, "WRITE", "ESCALATED_TO_HIGH", "magic number 불일치")
            await ops.trigger_high(pid, reason="magic_mismatch")

            return len(buf)

        # 규칙 1: 확장자 그룹별 엔트로피 임계값 (Stage1의 전역 엔트로피 탐지와는
        # 별개로, 이미 MEDIUM에 들어온 프로세스가 계속 고엔트로피로 쓰는지를
        # 파일 유형에 맞는 기준으로 재확인한다. 이미 압축된 포맷은 검사하지 않는다.
        threshold = group["entropy_threshold"]
        if threshold is not None:
            ent = shannon_entropy(buf[:ENTROPY_HEADER_SIZE])
            if ent >= threshold:
                print(
                    f"[MEDIUM] pid={pid} path={path} ext_group={group_name} "
                    f"entropy={ent:.2f}(threshold={threshold}) → High 격상"
                )
                log_medium_event(
                    pid, path, "WRITE", "ESCALATED_TO_HIGH",
                    f"high_entropy(ext={group_name},H={ent:.2f}>={threshold})",
                )
                await ops.trigger_high(
                    pid, reason=f"high_entropy_write(ext={group_name})"
                )

                return len(buf)

        buffered = ops._write_buffer_bytes[pid]
        group_limit = group["buffer_limit_bytes"]

        if buffered + len(buf) > group_limit:
            print(
                f"[MEDIUM] pid={pid} path={path} ext_group={group_name} "
                f"누적 버퍼 {buffered}B 상한({group_limit}B) 초과 → High 격상"
            )
            log_medium_event(
                pid, path, "WRITE", "ESCALATED_TO_HIGH",
                f"buffer_limit_exceeded(ext={group_name},{buffered}+{len(buf)}>{group_limit})",
            )
            await ops.trigger_high(pid, reason="buffer_limit_exceeded")

            return len(buf)

        # 규칙 5: 시스템 전역 버퍼 상한. 여러 PID가 동시에 MEDIUM에 몰려
        # 전역 메모리 사용량이 한계를 넘으면, 초과를 유발한 이 write의
        # 주체를 즉시 HIGH로 올려 버퍼를 회수한다.
        if ops._global_buffer_bytes + len(buf) > MEDIUM_GLOBAL_BUFFER_LIMIT_BYTES:
            print(
                f"[MEDIUM] pid={pid} path={path} 전역 버퍼 "
                f"{ops._global_buffer_bytes}B 상한({MEDIUM_GLOBAL_BUFFER_LIMIT_BYTES}B) 초과 → High 격상"
            )
            log_medium_event(
                pid, path, "WRITE", "ESCALATED_TO_HIGH",
                f"global_buffer_limit_exceeded({ops._global_buffer_bytes}+{len(buf)})",
            )
            await ops.trigger_high(pid, reason="global_buffer_limit_exceeded")

            return len(buf)

        ops._write_buffer[pid].append((fd, off, buf, path))
        ops._write_buffer_bytes[pid] = buffered + len(buf)
        ops._global_buffer_bytes += len(buf)

        print(
            f"[MEDIUM] pid={pid} trusted={trusted} ext_group={group_name} "
            f"path={path} off={off} size={file_size} → 버퍼 보관"
        )

        log_medium_event(
            pid, path, "WRITE", "BUFFERED",
            f"size={file_size} trusted={trusted} ext_group={group_name}",
        )

    else:
        print(f"[MEDIUM] pid={pid} trusted={trusted} path={path} size={file_size} → 대용량 MTD_DELAY")
        try:
            os.pwrite(fd, buf, off)
        except OSError:
            pass

    # 규칙 3: write "누적 횟수"가 아니라 MEDIUM 진입 후 "경과시간" 구간별로
    # 지연을 적용한다 (GuardFS 실측: 5초 지연이 최적, 10초는 더 늦춰도 개선 없음).
    elapsed = trio.current_time() - ops._medium_entered_at[pid]
    base_ms = _phase_delay_ms(elapsed, trusted)
    delay_sec = (base_ms / 1000.0) * group["delay_multiplier"]

    await trio.sleep(delay_sec)

    return len(buf)


# ========== 규칙 4: unlink 단계적 차단 ========== #
async def handle_unlink_medium(path: str, pid: int, ops) -> None:
    """
    MEDIUM 중 unlink는 실제로 지우지 않고 스테이징으로 옮긴다.
    - 호출자에게는 삭제가 성공한 것처럼 보이게 한다 (경로에서 사라짐).
    - LOW로 판정나면 실제로 삭제를 확정하고, HIGH로 격상되면 원래 자리로 복원한다.
    """
    staging_path = os.path.join(
        ops._staging_dir,
        f"unlink_{pid}_{time.time_ns()}_{os.path.basename(path)}",
    )

    try:
        os.rename(path, staging_path)
    except FileNotFoundError:
        return  # 이미 없는 파일 — 조용히 무시
    except OSError as e:
        print(f"[MEDIUM] pid={pid} path={path} unlink 스테이징 실패: {e} → 삭제 차단")
        return

    ops._unlink_staged[pid].append((path, staging_path))

    print(f"[MEDIUM] pid={pid} path={path} unlink 요청 → 스테이징 이동 (원본 보존)")
    log_medium_event(pid, path, "UNLINK", "STAGED", "삭제 요청을 스테이징으로 유도, 원본 보존")


def _finalize_unlink(pid: int, ops) -> None:
    """LOW 복귀: 스테이징으로 옮겨둔 삭제를 실제로 확정한다."""
    for orig_path, staging_path in ops._unlink_staged.pop(pid, []):
        try:
            os.unlink(staging_path)
            print(f"[COMMIT] pid={pid} path={orig_path} → 삭제 확정 (LOW 판정)")
            log_medium_event(pid, orig_path, "UNLINK", "CONFIRMED", "정상 판정 후 삭제 확정")
        except OSError as e:
            print(f"[COMMIT] pid={pid} path={orig_path} 삭제 확정 실패: {e}")


def _restore_unlink(pid: int, ops) -> None:
    """HIGH 격상/드롭: 스테이징으로 옮겨둔 파일을 원래 자리로 되돌린다."""
    for orig_path, staging_path in ops._unlink_staged.pop(pid, []):
        try:
            os.rename(staging_path, orig_path)
            print(f"[DROP] pid={pid} path={orig_path} → 삭제 취소, 원본 복원")
            log_medium_event(pid, orig_path, "UNLINK", "RESTORED", "HIGH 격상으로 삭제 취소, 원본 복원")
        except OSError as e:
            print(f"[DROP] pid={pid} path={orig_path} 복원 실패: {e}")


async def commit_buffers(pid: int, ops) -> None:
    buffers = ops._write_buffer.pop(pid, [])
    ops._write_buffer_bytes.pop(pid, None)
    ops._pid_trusted.pop(pid, None)
    ops._medium_entered_at.pop(pid, None)
    trunc_paths = ops._trunc_paths.pop(pid, set())

    # path별로 버퍼된 (off, buf)를 순서대로 모아, HIGH_VALUE 확장자면
    # 커밋 전에 구조 검증(규칙2)까지 마친 뒤에 실제로 적용한다.
    by_path: dict = {}
    for (fd, off, buf, path) in buffers:
        by_path.setdefault(path, []).append((off, buf))
        ops._global_buffer_bytes = max(0, ops._global_buffer_bytes - len(buf))

    truncated_already = set()

    for path, ordered_writes in by_path.items():
        # 첫 청크(off==0) 기준 magic byte는 기존과 동일하게 유지
        for off, buf in ordered_writes:
            if not validate_magic(path, buf, off):
                print(f"[COMMIT] pid={pid} path={path} 구조 깨짐(magic) → 커밋 취소")
                # trigger_high → handle_high_enter가 drop_buffers를 호출해
                # unlink 복원까지 전담한다 (여기서 중복 호출하지 않음).
                await ops.trigger_high(pid, reason="magic_mismatch_on_commit")
                return

        group_name = classify_extension(path)
        group = EXTENSION_GROUPS[group_name]
        is_truncated = path in trunc_paths

        if group["structural_check"]:
            final_content = _reconstruct_final_content(path, ordered_writes, is_truncated)
            if not structural_check(path, final_content):
                print(f"[COMMIT] pid={pid} path={path} 구조 깨짐(내부구조) → 커밋 취소")
                log_medium_event(pid, path, "COMMIT", "FAILED", "structural_check 실패")
                await ops.trigger_high(pid, reason="structural_check_failed")
                return

        try:
            if is_truncated and path not in truncated_already:
                open(path, "wb").close()
                truncated_already.add(path)

            with open(path, "r+b") as f:
                for off, buf in ordered_writes:
                    f.seek(off)
                    f.write(buf)

            print(f"[COMMIT] pid={pid} path={path} → 커밋 완료 ({len(ordered_writes)}개 write)")
            log_medium_event(pid, path, "COMMIT", "SUCCESS", "정상 판정 후 LOW 복귀")

        except FileNotFoundError:
            with open(path, "wb") as f:
                for off, buf in ordered_writes:
                    f.seek(off)
                    f.write(buf)

            truncated_already.add(path)
            print(f"[COMMIT] pid={pid} path={path} → 새 파일 커밋 완료 ({len(ordered_writes)}개 write)")
            log_medium_event(pid, path, "COMMIT", "SUCCESS", "새 파일 생성 후 커밋")

        except OSError as e:
            print(f"[COMMIT] pid={pid} path={path} 오류: {e}")
            log_medium_event(pid, path, "COMMIT", "FAILED", str(e))

    for staging_path in ops._staging_pid.pop(pid, []):
        try:
            os.unlink(staging_path)
        except OSError:
            pass

    _finalize_unlink(pid, ops)


async def drop_buffers(pid: int, ops) -> None:
    dropped = ops._write_buffer.pop(pid, [])
    ops._write_buffer_bytes.pop(pid, None)
    ops._pid_trusted.pop(pid, None)
    ops._medium_entered_at.pop(pid, None)
    ops._trunc_paths.pop(pid, None)

    for (_fd, _off, buf, _path) in dropped:
        ops._global_buffer_bytes = max(0, ops._global_buffer_bytes - len(buf))

    for staging_path in ops._staging_pid.pop(pid, []):
        try:
            os.unlink(staging_path)
        except OSError:
            pass

    _restore_unlink(pid, ops)

    print(f"[DROP] pid={pid} 버퍼 {len(dropped)}개 드롭 → 원본 보존")
    log_medium_event(pid, "", "DROP", "BUFFER_DROPPED", f"버퍼 {len(dropped)}개 드롭, 원본 보존")


async def validate_medium_buffers(pid: int, ops) -> bool:
    for (fd, off, buf, path) in ops._write_buffer.get(pid, []):
        if not validate_magic(path, buf, off):
            print(f"[VALIDATE] pid={pid} path={path} 구조 깨짐 감지")
            return True
    return False
