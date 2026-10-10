from __future__ import annotations

# medium.py
import errno
import io
import os
import stat
import time
import zipfile

import trio

from guardfs.common.config import (
    ENTROPY_HEADER_SIZE,
    EXTENSION_GROUPS,
    MEDIUM_DELAY_PHASES,
    MEDIUM_GLOBAL_BUFFER_LIMIT_BYTES,
    MEDIUM_SIZE_LIMIT,
)
from guardfs.common.paths import FILESECURITY_LOG_PATH
from guardfs.stage1.entropy import shannon_entropy


def log_medium_event(
    pid: int, path: str, action: str, result: str, reason: str = ""
) -> None:
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
    ".pdf": b"%PDF-",
    ".docx": b"PK",
    ".xlsx": b"PK",
    ".pptx": b"PK",
    ".jpg": b"\xff\xd8\xff",
    ".png": b"\x89PNG",
    ".zip": b"PK",
}


def validate_magic(path: str, buf: bytes, off: int) -> bool:
    if off != 0:
        return True

    ext = os.path.splitext(path)[1].lower()
    magic = MAGIC_BYTES.get(ext)

    if magic is None:
        return True

    return buf[: len(magic)] == magic


# ========== 규칙 1: 확장자 그룹 분류 ========== #
_EXT_TO_GROUP = {
    ext: group for group, cfg in EXTENSION_GROUPS.items() for ext in cfg["exts"]
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


def _reconstruct_final_content(
    path: str, ordered_writes: list, truncated: bool, source_fd: int | None = None
) -> bytes:
    """
    한 경로에 대해 버퍼된 (off, buf)들을 순서대로 적용한 최종 바이트를
    메모리에서 재구성한다. O_TRUNC로 열렸던 경우 원본을 무시하고 빈
    상태에서 시작하고, 아니면 디스크에 남아있는 원본 위에 얹는다.
    """

    if truncated:
        data = bytearray()
    elif source_fd is not None:
        data = bytearray()
        size = os.fstat(source_fd).st_size
        while len(data) < size:
            chunk = os.pread(source_fd, io.DEFAULT_BUFFER_SIZE, len(data))
            if not chunk:
                raise OSError(errno.EIO, "구조 검증용 원본 읽기 실패")
            data.extend(chunk)
    elif not os.path.exists(path):
        data = bytearray()
    else:
        try:
            with open(path, "rb") as f:
                data = bytearray(f.read())
        except OSError:
            data = bytearray()

    for off, buf in ordered_writes:
        if buf is None:
            # truncate: 축소 또는 0으로 채워 확장
            if off < len(data):
                del data[off:]
            elif off > len(data):
                data.extend(b"\x00" * (off - len(data)))

        # 0바이트 write는 파일 크기를 늘리지 않음
        if not buf:
            continue

        end = off + len(buf)

        if end > len(data):
            data.extend(b"\x00" * (end - len(data)))

        data[off:end] = buf

    return bytes(data)


def pending_file_view(ops, pid, fd, off=0, size=0):
    """같은 파일의 대기 write/truncate를 반영한 크기와 읽기 결과"""

    if off < 0 or size < 0:
        raise OSError(errno.EINVAL, "잘못된 read 범위")

    source_fd = ops._staging_origin_fd.get(fd, fd)

    if source_fd is None:
        source_fd = fd

    st = os.fstat(source_fd)
    identity = (st.st_dev, st.st_ino)
    held_fd = ops._buffer_fds.get(pid, {}).get(identity)

    changes = [
        (position, buf)
        for pending_fd, position, buf, _path in ops._write_buffer.get(pid, [])
        if held_fd is not None and pending_fd == held_fd
    ]

    logical_size = st.st_size

    for position, buf in changes:
        if buf is None:
            logical_size = position
        elif buf:
            logical_size = max(logical_size, position + len(buf))

    length = min(size, max(0, logical_size - off))
    data = bytearray(length)

    if length:
        original = os.pread(source_fd, length, off)
        data[: len(original)] = original

    # truncate로 제거된 바이트가 이후 확장에서 되살아나지 않게 설정
    for position, buf in changes:
        if buf is None:
            start = max(0, position - off)
            if start < length:
                data[start:] = b"\x00" * (length - start)

        elif buf:
            start = max(off, position)
            end = min(off + length, position + len(buf))

            if start < end:
                data[start - off : end - off] = buf[start - position : end - position]

    return logical_size, bytes(data)


def _phase_delay_ms(elapsed_sec: float, trusted: bool) -> int:
    for phase_end, untrusted_ms, trusted_ms in MEDIUM_DELAY_PHASES:
        if elapsed_sec < phase_end:
            return trusted_ms if trusted else untrusted_ms

    return MEDIUM_DELAY_PHASES[-1][2 if trusted else 1]


def _retain_buffer_fd(pid: int, fd: int, ops) -> int:
    """핸들 종료와 경로 재사용에 영향받지 않는 commit 대상을 보관한다."""
    origins = ops._staging_origin_fd
    new_file = fd in origins and origins[fd] is None
    target_fd = origins.get(fd, fd)
    if target_fd is None:
        target_fd = fd

    st = os.fstat(target_fd)
    identity = (st.st_dev, st.st_ino)
    retained = ops._buffer_fds[pid]
    held_fd = retained.get(identity)
    if held_fd is None:
        # 독립적인 파일 위치와 O_APPEND 없는 descriptor를 확보한다.
        # Linux /proc에서 열린 파일을 다시 열므로 경로 재사용을 따라가지 않는다.
        held_fd = os.open(f"/proc/self/fd/{target_fd}", os.O_RDWR)
        retained[identity] = held_fd

    if new_file:
        for fh, handle_fd in ops._fd_map.items():
            if handle_fd == fd:
                ops._buffer_new_files[pid][held_fd] = ops._staging_fh[fh]
                break
        else:
            raise OSError(errno.EBADF, "신규 staging 핸들을 찾을 수 없음")
    return held_fd


def _close_buffer_fds(pid: int, ops) -> None:
    error = None
    for held_fd in ops._buffer_fds.pop(pid, {}).values():
        try:
            os.close(held_fd)
        except OSError as e:
            error = e
    ops._buffer_new_files.pop(pid, None)
    if error is not None:
        raise error


def _pwrite_all(fd: int, buf: bytes, off: int) -> None:
    view = memoryview(buf)
    written = 0
    while written < len(view):
        count = os.pwrite(fd, view[written:], off + written)
        if count <= 0:
            raise OSError(errno.EIO, "지연 write 반영 실패")
        written += count


def _rebind_staging_handles(ops, pid, source_identity, target_fd) -> None:
    """commit 또는 원본 복귀 시 열린 staging 핸들을 연결"""
    replacements = []

    try:
        # dup 실패 전에 기존 핸들을 바꾸거나 닫지 않는다.
        for fh in list(ops._staging_fh):
            if ops._fh_info.get(fh, (-1, "?", 0))[0] != pid:
                continue
            old_fd = ops._fd_map.get(fh)
            if old_fd is None:
                continue
            origin_fd = ops._staging_origin_fd.get(old_fd)
            source_fd = old_fd if origin_fd is None else origin_fd
            st = os.fstat(source_fd)
            if (st.st_dev, st.st_ino) == source_identity:
                replacements.append((fh, old_fd, origin_fd, os.dup(target_fd)))
    except OSError:
        for _fh, _old_fd, _origin_fd, replacement in replacements:
            os.close(replacement)

        raise

    cleanup_error = None

    for fh, old_fd, origin_fd, replacement in replacements:
        ops._fd_map[fh] = replacement
        ops._staging_fh.pop(fh, None)
        ops._staging_origin_fd.pop(old_fd, None)
        for obsolete_fd in (old_fd, origin_fd):
            if obsolete_fd is not None:
                try:
                    os.close(obsolete_fd)
                except OSError as e:
                    cleanup_error = e

    # 핸들이 이미 release된 경우에도 가상 inode를 확정
    finish = getattr(ops, "_finish_staging_commit", None)

    if finish is not None:
        finish(pid, source_identity, target_fd)

    if cleanup_error is not None:
        log_medium_event(pid, "", "COMMIT", "HANDLE_CLEANUP_FAILED", str(cleanup_error))


def _publish_new_file(path: str, source_fd: int, pid: int, ops) -> None:
    """새 파일은 배타적으로 생성한다. 기존 경로를 덮어쓰지 않는다."""
    st = os.fstat(source_fd)
    target_fd = os.open(
        path, os.O_RDWR | os.O_CREAT | os.O_EXCL, stat.S_IMODE(st.st_mode)
    )
    try:
        off = 0
        while off < st.st_size:
            chunk = os.pread(source_fd, io.DEFAULT_BUFFER_SIZE, off)
            if not chunk:
                raise OSError(errno.EIO, "staging 파일 읽기 실패")
            _pwrite_all(target_fd, chunk, off)
            off += len(chunk)
        os.ftruncate(target_fd, st.st_size)
        _rebind_staging_handles(ops, pid, (st.st_dev, st.st_ino), target_fd)
    finally:
        os.close(target_fd)


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

    # 비신뢰 프로세스 또는 truncate 대기 중인 파일은 버퍼링한다.
    # truncate 대기가 없는 신뢰 프로세스는 기존 크기 기준을 유지한다.
    target_fd = ops._staging_origin_fd.get(fd, fd)
    if target_fd is None:
        target_fd = fd
    target_stat = os.fstat(target_fd)
    target_identity = (target_stat.st_dev, target_stat.st_ino)
    held_target = ops._buffer_fds.get(pid, {}).get(target_identity)
    has_pending_truncate = any(
        pending_fd == held_target and pending_buf is None
        for pending_fd, _off, pending_buf, _path in ops._write_buffer.get(pid, [])
    )

    if (
        fd in ops._staging_origin_fd
        or has_pending_truncate
        or not trusted
        or file_size < MEDIUM_SIZE_LIMIT
    ):
        if not validate_magic(path, buf, off):
            print(f"[MEDIUM] pid={pid} path={path} magic number 불일치 → High 격상")

            log_medium_event(
                pid,
                path,
                "WRITE",
                "ESCALATED_TO_HIGH",
                "magic number 불일치",
            )

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
                    f"[MEDIUM] pid={pid} path={path} "
                    f"ext_group={group_name} "
                    f"entropy={ent:.2f}(threshold={threshold}) → High 격상"
                )

                log_medium_event(
                    pid,
                    path,
                    "WRITE",
                    "ESCALATED_TO_HIGH",
                    f"high_entropy(ext={group_name}, H={ent:.2f}>={threshold})",
                )

                await ops.trigger_high(
                    pid,
                    reason=f"high_entropy_write(ext={group_name})",
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
                pid,
                path,
                "WRITE",
                "ESCALATED_TO_HIGH",
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
                pid,
                path,
                "WRITE",
                "ESCALATED_TO_HIGH",
                f"global_buffer_limit_exceeded({ops._global_buffer_bytes}+{len(buf)})",
            )
            await ops.trigger_high(pid, reason="global_buffer_limit_exceeded")

            return len(buf)

        held_fd = _retain_buffer_fd(pid, fd, ops)

        ops._write_buffer[pid].append((held_fd, off, buf, path))
        ops._write_buffer_bytes[pid] = buffered + len(buf)
        ops._global_buffer_bytes += len(buf)

        print(
            f"[MEDIUM] pid={pid} trusted={trusted} ext_group={group_name} "
            f"path={path} off={off} size={file_size} → 버퍼 보관"
        )

        log_medium_event(
            pid,
            path,
            "WRITE",
            "BUFFERED",
            f"size={file_size} trusted={trusted} ext_group={group_name}",
        )

    else:
        print(
            f"[MEDIUM] pid={pid} trusted={trusted} path={path} size={file_size} → 대용량 MTD_DELAY"
        )
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
        # 이미 없는 파일 — 조용히 무시
        return
    except OSError as e:
        print(f"[MEDIUM] pid={pid} path={path} unlink 스테이징 실패: {e} → 삭제 차단")

        return

    st = os.lstat(staging_path)
    ops._unlink_identity[staging_path] = (st.st_dev, st.st_ino)
    ops._unlink_staged[pid].append((path, staging_path))

    print(f"[MEDIUM] pid={pid} path={path} unlink 요청 → 스테이징 이동 (원본 보존)")

    log_medium_event(
        pid, path, "UNLINK", "STAGED", "삭제 요청을 스테이징으로 유도, 원본 보존"
    )


def _finalize_unlink(pid: int, ops) -> None:
    """LOW 복귀: 삭제를 확정하되 실패한 이력은 보존한다."""
    remaining = []
    for orig_path, staging_path in ops._unlink_staged.pop(pid, []):
        try:
            st = os.lstat(staging_path)
            expected = ops._unlink_identity.get(staging_path)
            if expected != (st.st_dev, st.st_ino):
                raise OSError(errno.ESTALE, "삭제 staging 파일 정체성 불일치")
            os.unlink(staging_path)
            ops._unlink_identity.pop(staging_path, None)
            print(f"[COMMIT] pid={pid} path={orig_path} → 삭제 확정 (LOW 판정)")
            log_medium_event(
                pid, orig_path, "UNLINK", "CONFIRMED", "정상 판정 후 삭제 확정"
            )
        except FileNotFoundError:
            ops._unlink_identity.pop(staging_path, None)
        except OSError as e:
            remaining.append((orig_path, staging_path))
            log_medium_event(pid, orig_path, "UNLINK", "FINALIZE_FAILED", str(e))
    if remaining:
        ops._unlink_staged[pid].extend(remaining)


def _restore_unlink(pid: int, ops) -> None:
    """목적지를 덮어쓰지 않고 복원한다. 충돌 원본은 staging에 보존한다."""

    entries = ops._unlink_staged.pop(pid, [])
    retained = []

    # 같은 PID의 반복 삭제에서는 최근 버전부터 복원을 시도
    for orig_path, staging_path in reversed(entries):
        try:
            st = os.lstat(staging_path)
            expected = ops._unlink_identity.get(staging_path)

            if expected != (st.st_dev, st.st_ino):
                raise OSError(errno.ESTALE, "복원 staging 파일 정체성 불일치")
            # link는 목적지가 존재하면 실패하므로 덮어쓰지 않음
            # exist() 검사 후 rename하는 방식의 동시 생성 경쟁을 피함
            os.link(
                staging_path,
                orig_path,
                follow_symlinks=False,
            )
        except FileExistsError:
            # 목적지의 새 파일은 유지
            retained.append((orig_path, staging_path))

            print(
                f"[RESTORE CONFLICT] pid={pid} path={orig_path} "
                f"→ 기존 파일 유지, 원본 보존={staging_path}"
            )
            log_medium_event(
                pid,
                orig_path,
                "UNLINK",
                "RESTORE_CONFLICT",
                f"충돌 원본 보존: {staging_path}",
            )
            continue
        except OSError as e:
            # 복원 실패 시 원본과 이력을 버리지 않음
            retained.append((orig_path, staging_path))

            log_medium_event(
                pid,
                orig_path,
                "UNLINK",
                "RESTORE_FAILED",
                f"{e}; 원본 보존={staging_path}",
            )
            continue

        try:
            os.unlink(staging_path)
        except OSError as e:
            # 목적지 복원은 성공했지만 staging 정리는 실패한 경우
            retained.append((orig_path, staging_path))

            log_medium_event(
                pid,
                orig_path,
                "UNLINK",
                "RESTORE_CLEANUP_FAILED",
                f"{e}; staging={staging_path}",
            )
            continue

        ops._unlink_identity.pop(staging_path, None)
        print(f"[DROP] pid={pid} path={orig_path} → 삭제 취소, 원본 복원")
        log_medium_event(
            pid,
            orig_path,
            "UNLINK",
            "RESTORED",
            "목적지를 덮어쓰지 않고 복원",
        )

    if retained:
        # 충돌 원본을 후속 LOW 삭제 확정 목록과 분리
        ops._unlink_recovery[pid].extend(reversed(retained))


def _reconstruct_pending_content(path, changes):
    """write와 truncate를 순서대로 적용한 구조 검증용 내용."""

    try:
        with open(path, "rb") as f:
            data = bytearray(f.read())
    except FileNotFoundError:
        data = bytearray()

    for off, buf in changes:
        if buf is None:
            if off < len(data):
                del data[off:]
            elif off > len(data):
                data.extend(b"\x00" * (off - len(data)))
        elif buf:
            end = off + len(buf)

            if end > len(data):
                data.extend(b"\x00" * (end - len(data)))

            data[off:end] = buf

    return bytes(data)


async def commit_buffers(pid: int, ops) -> None:
    buffers = ops._write_buffer.pop(pid, [])
    ops._write_buffer_bytes.pop(pid, None)
    ops._pid_trusted.pop(pid, None)
    ops._medium_entered_at.pop(pid, None)
    ops._trunc_paths.pop(pid, None)

    by_file = {}
    for fd, off, buf, path in buffers:
        entry = by_file.setdefault(fd, {"path": path, "changes": []})
        entry["path"] = path
        entry["changes"].append((off, buf))
        if buf is not None:
            ops._global_buffer_bytes = max(0, ops._global_buffer_bytes - len(buf))

    new_files = dict(ops._buffer_new_files.get(pid, {}))
    identities = {
        held_fd: identity for identity, held_fd in ops._buffer_fds.get(pid, {}).items()
    }
    applied = set()
    rejected = False
    failed = False
    try:
        # 모든 대상의 검증이 끝나기 전에는 원본에 적용하지 않는다.
        for fd, entry in by_file.items():
            path, changes = entry["path"], entry["changes"]
            for off, buf in changes:
                if buf is not None and not validate_magic(path, buf, off):
                    rejected = True

                    await ops.trigger_high(pid, reason="magic_mismatch_on_commit")
                    return
            group = EXTENSION_GROUPS[classify_extension(path)]
            if group["structural_check"]:
                final_content = _reconstruct_final_content(
                    path, changes, False, source_fd=fd
                )
                if not structural_check(path, final_content):
                    log_medium_event(
                        pid,
                        path,
                        "COMMIT",
                        "VALIDATION_FAILED",
                        "structural_check 실패; 원본 미반영",
                    )
                    rejected = True
                    await ops.trigger_high(pid, reason="structural_check_failed")
                    return

        for fd, entry in by_file.items():
            path, changes = entry["path"], entry["changes"]
            try:
                for off, buf in changes:
                    if buf is None:
                        os.ftruncate(fd, off)
                    elif buf:
                        _pwrite_all(fd, buf, off)
                if fd in new_files:
                    _publish_new_file(path, fd, pid, ops)
                else:
                    _rebind_staging_handles(ops, pid, identities[fd], fd)
                applied.add(fd)
                print(
                    f"[COMMIT] pid={pid} path={path} → 파일 반영 완료 ({len(changes)}개 작업)"
                )
                log_medium_event(
                    pid,
                    path,
                    "COMMIT",
                    "FILE_APPLIED",
                    "원래 파일에 순서대로 반영; PID 전체 성공과 구분",
                )
            except OSError as e:
                failed = True
                # 현재 파일도 일부 변경됐을 수 있다. rollback 성공으로 기록하지 않음
                log_medium_event(
                    pid,
                    path,
                    "COMMIT",
                    "APPLY_FAILED",
                    f"{e}; 부분 반영 가능, 이후 적용 중단",
                )
                break

        if not failed:
            _finalize_unlink(pid, ops)
            log_medium_event(
                pid,
                "",
                "COMMIT",
                "DATA_APPLIED",
                "모든 파일 데이터 적용 완료; 삭제 확정/정리 오류는 별도 로그 확인",
            )

    except OSError as e:
        failed = True
        log_medium_event(
            pid, "", "COMMIT", "IO_FAILED", f"{e}; 적용 완료 파일 수={len(applied)}"
        )

    finally:
        try:
            if not rejected:
                preserve_staging = set()

                for fd, staging_path in new_files.items():
                    if fd in applied:
                        continue
                    path = by_file[fd]["path"]
                    preserve_staging.add(staging_path)
                    record = (path, staging_path)

                    if record not in ops._staging_recovery[pid]:
                        ops._staging_recovery[pid].append(record)
                    finish = getattr(ops, "_finish_staging_recovery", None)

                    if finish is not None:
                        finish(pid, identities[fd])
                    log_medium_event(
                        pid, path, "COMMIT", "STAGING_PRESERVED", staging_path
                    )

                if failed:
                    for fd, entry in by_file.items():
                        if fd not in applied:
                            log_medium_event(
                                pid,
                                entry["path"],
                                "COMMIT",
                                "NOT_COMPLETED",
                                "실패 또는 미적용; 전체 commit 성공 아님",
                            )

                for staging_path in ops._staging_pid.pop(pid, []):
                    if staging_path in preserve_staging:
                        continue
                    try:
                        os.unlink(staging_path)
                    except FileNotFoundError:
                        continue
                    except OSError as e:
                        log_medium_event(
                            pid, staging_path, "COMMIT", "CLEANUP_FAILED", str(e)
                        )
        finally:
            _close_buffer_fds(pid, ops)


async def drop_buffers(pid: int, ops) -> None:
    dropped = ops._write_buffer.pop(pid, [])

    ops._write_buffer_bytes.pop(pid, None)
    ops._pid_trusted.pop(pid, None)
    ops._medium_entered_at.pop(pid, None)
    ops._trunc_paths.pop(pid, None)

    for _fd, _off, buf, _path in dropped:
        if buf is not None:
            ops._global_buffer_bytes = max(
                0,
                ops._global_buffer_bytes - len(buf),
            )

    try:
        new_files = ops._buffer_new_files.get(pid, {})
        # 기존 O_TRUNC 핸들은 변경하지 않은 원본으로 돌아간다.
        for identity, held_fd in list(ops._buffer_fds.get(pid, {}).items()):
            if held_fd not in new_files:
                _rebind_staging_handles(ops, pid, identity, held_fd)

        finish = getattr(ops, "_finish_staging_drop", None)

        if finish is not None:
            finish(pid)

        for staging_path in ops._staging_pid.pop(pid, []):
            try:
                os.unlink(staging_path)
            except FileNotFoundError:
                continue
            except OSError as e:
                log_medium_event(pid, staging_path, "DROP", "CLEANUP_FAILED", str(e))

        _restore_unlink(pid, ops)

        print(f"[DROP] pid={pid} 버퍼 {len(dropped)}개 드롭 → 원본 보존")
        log_medium_event(
            pid, "", "DROP", "BUFFER_DROPPED", f"버퍼 {len(dropped)}개 드롭, 원본 보존"
        )

    finally:
        _close_buffer_fds(pid, ops)


async def validate_medium_buffers(pid: int, ops) -> bool:
    for fd, off, buf, path in ops._write_buffer.get(pid, []):
        if buf is None:
            continue

        if not validate_magic(path, buf, off):
            print(f"[VALIDATE] pid={pid} path={path} 구조 깨짐 감지")
            return True

    return False
