#!/usr/bin/env python3
import os
import sys
import errno
import time
import math
from dataclasses import dataclass
from typing import Optional, Dict, Tuple
from collections import defaultdict
from enum import Enum

import pyfuse3
import trio
from stage1 import Stage1Detector, EventLogger


def _full_path(root: str, path: str) -> str:
    if path.startswith("/"):
        path = path[1:]
    return os.path.join(root, path)


@dataclass
class FsEvent:
    ts_ns: int
    pid: int
    op: str
    path: str
    size: int = 0
    off: int = -1
    flags: int = 0
    entropy: Optional[float] = None
    new_path: Optional[str] = None   # rename 시 목적지 경로

class ProcState(str, Enum):
    LOW = "LOW"
    SUSPICIOUS = "SUSPICIOUS"


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent

class PidStats:
    def __init__(self):
        self.write_count = 0
        self.entropy_sum = 0.0
        self.rename_count = 0
        self.unlink_count = 0
        self.files = set()

    def reset(self) -> None:
        self.write_count = 0
        self.entropy_sum = 0.0
        self.rename_count = 0
        self.unlink_count = 0
        self.files.clear()

    def mean_entropy(self) -> float:
        if self.write_count == 0:
            return 0.0
        return self.entropy_sum / self.write_count


async def stats_collector(
    recv_chan: trio.MemoryReceiveChannel,
    log_path: str,
    honeypot_dir: str,
    ops: "Passthrough",
) -> None:
    """
    [3번 수정] 역할 분리
    - EventLogger   : 모든 이벤트를 JSONL로 저장
    - PidStats      : 1초 윈도우 통계 집계 (기존 로직 유지)
    - Stage1Detector: 세 가지 탐지기로 즉시 판정 → mark_suspect
    """
    WINDOW_S = 1.0
    WRITE_TH = 5
    ENTROPY_TH = 1.0
    RENAME_TH = 10
    UNLINK_TH = 10

    stats = defaultdict(PidStats)
    logger = EventLogger(log_path)
    stage1 = Stage1Detector(honeypot_dir)

    next_tick = trio.current_time() + WINDOW_S

    try:
        async with recv_chan:
            while True:
                timeout = max(0.0, next_tick - trio.current_time())

                with trio.move_on_after(timeout) as scope:
                    try:
                        ev = await recv_chan.receive()
                    except trio.EndOfChannel:
                        break

                if scope.cancelled_caught:
                    # 1초 윈도우 통계 기반 판정 (기존 로직 유지)
                    for pid, st in list(stats.items()):
                        mean_ent = st.mean_entropy()
                        suspicious = (
                            (st.write_count >= WRITE_TH and mean_ent >= ENTROPY_TH)
                            or (st.rename_count >= RENAME_TH)
                            or (st.unlink_count >= UNLINK_TH)
                        )
                        if suspicious and pid > 0:
                            print(
                                f"[SUSPICIOUS] pid={pid} "
                                f"writes={st.write_count} mean_entropy={mean_ent:.2f} "
                                f"renames={st.rename_count} unlinks={st.unlink_count} "
                                f"unique_files={len(st.files)}"
                            )
                            await ops.mark_suspect(
                                pid,
                                reason="stat_anomaly",
                                path=""
                            )
                        st.reset()

                    next_tick += WINDOW_S
                    continue

                # 로그 저장
                logger.write(ev)

                # Stage1 즉시 탐지 (하나라도 걸리면 바로 mark_suspect)
                await stage1.check(ev, ops)

                # 통계 집계
                st = stats[ev.pid]
                if ev.op == "write":
                    st.write_count += 1
                    st.entropy_sum += float(ev.entropy or 0.0)
                    st.files.add(ev.path)
                elif ev.op == "rename":
                    st.rename_count += 1
                elif ev.op == "unlink":
                    st.unlink_count += 1
    finally:
        logger.close()


class Passthrough(pyfuse3.Operations):
    def __init__(self, root: str):
        super().__init__()
        self.root = os.path.realpath(root)

        self._inode_path: Dict[int, str] = {pyfuse3.ROOT_INODE: self.root}
        self._fd_map: Dict[int, int] = {}
        self._next_fh = 1

        self._fh_info: Dict[int, Tuple[int, str, int]] = {}

        # [수정] opendir에서 발급한 fh → 해당 디렉토리 경로 매핑
        self._dir_fh_path: Dict[int, str] = {}

        self._send_chan, self._recv_chan = trio.open_memory_channel(10000)
        self._stage2_send, self._stage2_recv = trio.open_memory_channel(1000)

        # [수정 2번] 로그 파일을 underlay 바깥(프로젝트 루트)에 저장
        self._log_path = os.path.join(os.path.dirname(self.root), "guardfs_log.jsonl")

        self._pid_lock = trio.Lock()

        # PID 상태 관리
        self._proc_state: Dict[int, ProcState] = {}

        # 이미 2단계 큐에 들어간 PID 중복 등록 방지
        self._queued_stage2: set[int] = set()

    # ------------------------------------------------------------------ helpers

    def _resolve_path(self, parent_inode: int, name: bytes) -> str:
        """parent_inode로부터 자식 경로를 조합해 반환한다."""
        parent_path = self._inode_path.get(parent_inode)
        if parent_path is None:
            raise pyfuse3.FUSEError(errno.ENOENT)
        return os.path.join(parent_path, name.decode("utf-8", "surrogateescape"))

    def _register_inode(self, path: str) -> os.stat_result:
        """path를 stat하고 inode → path 매핑에 등록한 뒤 stat 결과를 반환한다."""
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            raise pyfuse3.FUSEError(errno.ENOENT)
        self._inode_path[st.st_ino] = path
        return st

    def _stat_to_attr(self, st: os.stat_result) -> pyfuse3.EntryAttributes:
        """os.stat_result → pyfuse3.EntryAttributes 변환."""
        attr = pyfuse3.EntryAttributes()
        attr.st_ino = st.st_ino
        attr.st_mode = st.st_mode
        attr.st_nlink = st.st_nlink
        attr.st_uid = st.st_uid
        attr.st_gid = st.st_gid
        attr.st_rdev = st.st_rdev
        attr.st_size = st.st_size
        attr.st_blksize = st.st_blksize
        attr.st_blocks = st.st_blocks
        attr.st_atime_ns = int(st.st_atime * 1e9)
        attr.st_mtime_ns = int(st.st_mtime * 1e9)
        attr.st_ctime_ns = int(st.st_ctime * 1e9)
        attr.entry_timeout = 1.0
        attr.attr_timeout = 1.0
        return attr

    def _emit(self, ev: FsEvent) -> None:
        try:
            self._send_chan.send_nowait(ev)
        except trio.WouldBlock:
            pass

    async def mark_suspect(self, pid: int, reason: str = "", path: str = "") -> None:
        if pid <= 0:
            return

        async with self._pid_lock:
            prev = self._proc_state.get(pid, ProcState.LOW)

            # 상태 승격
            if prev == ProcState.LOW:
                self._proc_state[pid] = ProcState.SUSPICIOUS
                print(f"[STATE] pid={pid} LOW -> SUSPICIOUS reason={reason}")

            # 이미 큐에 올라간 PID면 중복 전송 방지
            if pid in self._queued_stage2:
                return

            self._queued_stage2.add(pid)

        await self._stage2_send.send({
            "pid": pid,
            "reason": reason,
            "path": path,
            "ts": time.time()
        })

    async def get_proc_state(self, pid: int) -> ProcState:
        if pid <= 0:
            return ProcState.LOW
        async with self._pid_lock:
            return self._proc_state.get(pid, ProcState.LOW)

    # ------------------------------------------------------------------ FUSE ops

    async def access(self, inode, mode, ctx=None):
        return

    async def getattr(self, inode, ctx=None):
        p = self._inode_path.get(inode)
        if p is None:
            raise pyfuse3.FUSEError(errno.ENOENT)
        st = os.lstat(p)
        return self._stat_to_attr(st)

    async def lookup(self, parent_inode, name, ctx=None):
        # [수정] ROOT_INODE 고정 → parent_inode 기반 경로 조합
        p = self._resolve_path(parent_inode, name)
        st = self._register_inode(p)

        pid = ctx.pid if ctx is not None else -1
        self._emit(FsEvent(ts_ns=time.time_ns(), pid=pid, op="lookup", path=p))
        return self._stat_to_attr(st)

    async def create(self, parent_inode, name, mode, flags, ctx=None):
        # [수정] ROOT_INODE 고정 → parent_inode 기반 경로 조합
        p = self._resolve_path(parent_inode, name)

        pid = ctx.pid if ctx is not None else -1

        try:
            fd = os.open(p, flags | os.O_CREAT, mode)
        except OSError as e:
            raise pyfuse3.FUSEError(e.errno)

        st = self._register_inode(p)

        fh = self._next_fh
        self._next_fh += 1
        self._fd_map[fh] = fd
        self._fh_info[fh] = (pid, p, flags)
        self._emit(FsEvent(ts_ns=time.time_ns(), pid=pid, op="create", path=p, flags=flags))

        fi = pyfuse3.FileInfo()
        fi.fh = fh
        return fi, self._stat_to_attr(st)

    async def mkdir(self, parent_inode, name, mode, ctx=None):
        # [수정] ROOT_INODE 고정 → parent_inode 기반 경로 조합
        p = self._resolve_path(parent_inode, name)

        pid = ctx.pid if ctx is not None else -1

        try:
            os.mkdir(p, mode)
        except OSError as e:
            raise pyfuse3.FUSEError(e.errno)

        self._register_inode(p)
        self._emit(FsEvent(ts_ns=time.time_ns(), pid=pid, op="mkdir", path=p))

    async def rmdir(self, parent_inode, name, ctx=None):
        # [수정] ROOT_INODE 고정 → parent_inode 기반 경로 조합
        p = self._resolve_path(parent_inode, name)

        pid = ctx.pid if ctx is not None else -1

        try:
            os.rmdir(p)
        except OSError as e:
            raise pyfuse3.FUSEError(e.errno)

        self._emit(FsEvent(ts_ns=time.time_ns(), pid=pid, op="rmdir", path=p))

    async def opendir(self, inode, ctx=None):
        # [수정] fh 고정값 1 → inode별 fh 발급, 경로 매핑 저장
        p = self._inode_path.get(inode)
        if p is None:
            raise pyfuse3.FUSEError(errno.ENOENT)

        fh = self._next_fh
        self._next_fh += 1
        self._dir_fh_path[fh] = p

        pid = ctx.pid if ctx is not None else -1
        self._emit(FsEvent(ts_ns=time.time_ns(), pid=pid, op="opendir", path=p))
        return fh

    async def readdir(self, fh, off, token):
        # [수정] fh == 1 고정 → fh로 경로 조회
        dir_path = self._dir_fh_path.get(fh)
        if dir_path is None:
            raise pyfuse3.FUSEError(errno.EBADF)

        with os.scandir(dir_path) as it:
            entries = []
            for e in it:
                try:
                    st = e.stat(follow_symlinks=False)
                except FileNotFoundError:
                    continue

                full = os.path.join(dir_path, e.name)
                self._inode_path[st.st_ino] = full
                entries.append((e.name.encode("utf-8", "surrogateescape"), self._stat_to_attr(st)))

        for i, (name_b, attr) in enumerate(entries[int(off):], start=int(off)):
            if not pyfuse3.readdir_reply(token, name_b, attr, i + 1):
                break

    async def releasedir(self, fh):
        # [수정] opendir에서 발급한 fh 정리
        self._dir_fh_path.pop(fh, None)

    async def open(self, inode, flags, ctx=None):
        p = self._inode_path.get(inode)
        if p is None:
            raise pyfuse3.FUSEError(errno.ENOENT)

        try:
            fd = os.open(p, flags)
        except OSError as e:
            raise pyfuse3.FUSEError(e.errno)

        fh = self._next_fh
        self._next_fh += 1
        self._fd_map[fh] = fd

        pid = ctx.pid if ctx is not None else -1
        self._fh_info[fh] = (pid, p, flags)
        self._emit(FsEvent(ts_ns=time.time_ns(), pid=pid, op="open", path=p, flags=flags))

        fi = pyfuse3.FileInfo()
        fi.fh = fh
        fi.direct_io = False
        return fi

    async def read(self, fh, off, size):
        fd = self._fd_map.get(fh)
        if fd is None:
            raise pyfuse3.FUSEError(errno.EBADF)

        pid, path, _flags = self._fh_info.get(fh, (-1, "?", 0))
        self._emit(FsEvent(ts_ns=time.time_ns(), pid=pid, op="read", path=path, size=size, off=off))

        os.lseek(fd, off, os.SEEK_SET)
        try:
            return os.read(fd, size)
        except OSError as e:
            raise pyfuse3.FUSEError(e.errno)

    async def write(self, fh, off, buf):
        fd = self._fd_map.get(fh)
        if fd is None:
            raise pyfuse3.FUSEError(errno.EBADF)

        pid, path, _flags = self._fh_info.get(fh, (-1, "?", 0))
        ent = shannon_entropy(buf)
        self._emit(
            FsEvent(
                ts_ns=time.time_ns(),
                pid=pid,
                op="write",
                path=path,
                size=len(buf),
                off=off,
                entropy=ent,
            )
        )

        try:
            if hasattr(os, "pwrite"):
                n = os.pwrite(fd, buf, off)
            else:
                os.lseek(fd, off, os.SEEK_SET)
                n = os.write(fd, buf)
            return n
        except OSError as e:
            raise pyfuse3.FUSEError(e.errno)

    async def truncate(self, inode, size, ctx=None):
        p = self._inode_path.get(inode)
        if p is None:
            raise pyfuse3.FUSEError(errno.ENOENT)

        pid = ctx.pid if ctx is not None else -1

        try:
            with open(p, "r+b") as f:
                f.truncate(size)
        except OSError as e:
            raise pyfuse3.FUSEError(e.errno)

        self._emit(FsEvent(ts_ns=time.time_ns(), pid=pid, op="truncate", path=p, size=size))

    async def ftruncate(self, fh, size):
        fd = self._fd_map.get(fh)
        if fd is None:
            raise pyfuse3.FUSEError(errno.EBADF)

        pid, path, _flags = self._fh_info.get(fh, (-1, "?", 0))

        try:
            os.ftruncate(fd, size)
        except OSError as e:
            raise pyfuse3.FUSEError(e.errno)

        self._emit(FsEvent(ts_ns=time.time_ns(), pid=pid, op="ftruncate", path=path, size=size))

    async def unlink(self, parent_inode, name, ctx=None):
        # [수정] ROOT_INODE 고정 → parent_inode 기반 경로 조합
        p = self._resolve_path(parent_inode, name)

        pid = ctx.pid if ctx is not None else -1

        try:
            os.unlink(p)
        except OSError as e:
            raise pyfuse3.FUSEError(e.errno)

        self._emit(FsEvent(ts_ns=time.time_ns(), pid=pid, op="unlink", path=p))

    async def rename(self, parent_inode_old, name_old, parent_inode_new, name_new, flags, ctx=None):
        # [수정] ROOT_INODE 고정 → parent_inode 기반 경로 조합
        oldp = self._resolve_path(parent_inode_old, name_old)
        newp = self._resolve_path(parent_inode_new, name_new)

        pid = ctx.pid if ctx is not None else -1

        try:
            os.rename(oldp, newp)
        except OSError as e:
            raise pyfuse3.FUSEError(e.errno)

        # [수정 4번] from/to를 new_path 필드로 합쳐서 한 이벤트로 emit
        self._emit(FsEvent(ts_ns=time.time_ns(), pid=pid, op="rename", path=oldp, new_path=newp))

    async def release(self, fh):
        pid, path, flags = self._fh_info.pop(fh, (-1, "?", 0))
        self._emit(FsEvent(ts_ns=time.time_ns(), pid=pid, op="release", path=path, flags=flags))

        fd = self._fd_map.pop(fh, None)
        if fd is not None:
            os.close(fd)

async def stage2_worker(recv_chan, ops: "Passthrough"):
    async with recv_chan:
        async for item in recv_chan:
            pid = item["pid"]
            reason = item["reason"]
            path = item["path"]

            print(f"[STAGE2] received pid={pid} reason={reason} path={path}")

            # 임시 2단계 분석
            if "honeypot" in reason:
                risk = 0.95
            else:
                risk = 0.5

            print(f"[STAGE2] pid={pid} analyzed risk={risk}")

            # 분석 완료 후 큐 등록 해제
            async with ops._pid_lock:
                ops._queued_stage2.discard(pid)

async def main(mountpoint: str, root: str):
    honeypot_dir = os.path.join(os.path.realpath(root), "honeypot")
    ops = Passthrough(root)
    pyfuse3.init(ops, mountpoint, set())
    try:
        async with trio.open_nursery() as nursery:
            nursery.start_soon(
                stats_collector,
                ops._recv_chan,
                ops._log_path,
                honeypot_dir,
                ops,
            )
            nursery.start_soon(stage2_worker, ops._stage2_recv, ops)
            
            await pyfuse3.main()
    finally:
        pyfuse3.close(unmount=True)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python passthrough.py <MOUNTPOINT> <UNDERLAY>")
        sys.exit(2)
    trio.run(main, sys.argv[1], sys.argv[2])
