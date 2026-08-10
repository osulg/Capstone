#!/usr/bin/env python3
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import errno
import time
import json
import stat as stat_mod
from dataclasses import dataclass
from typing import Optional, Dict, Tuple
from collections import defaultdict
from enum import Enum
import joblib
import pandas as pd

import pyfuse3
import trio
from stage1 import Stage1Detector, EventLogger
from stage1.entropy import shannon_entropy
from stage2.stage2_worker import stage2_worker
from stage2.states import ProcState

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

async def stats_collector(
    recv_chan: trio.MemoryReceiveChannel,
    log_path: str,
    honeypot_dir: str,
    ops: "Passthrough",
) -> None:
    """
    - EventLogger   : 모든 이벤트를 JSONL로 저장
    - PidStats      : PID별 최근 행동 통계 집계
    - Stage1Detector: 경량 탐지 수행
    """
    WINDOW_S = 1.0
    WRITE_TH = 2
    ENTROPY_TH = 0.1
    RENAME_TH = 2
    UNLINK_TH = 2

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
                    for pid, st in list(stats.items()):
                        mean_ent = st.mean_entropy()
                        suspicious = (
                            (st.counts["O_sum"] >= WRITE_TH and mean_ent >= ENTROPY_TH)
                            or (st.counts["D_sum"] >= RENAME_TH)
                            or (st.counts["D_sum"] >= UNLINK_TH)
                        )

                        if suspicious and pid > 0:
                            feature_row = st.to_feature_row()

                            print(
                                f"[SUSPICIOUS] pid={pid} "
                                f"O_sum={st.counts['O_sum']} E_sum={mean_ent:.2f} "
                                f"D_sum={st.counts['D_sum']}"
                            )

                            await ops.mark_suspect(
                                pid,
                                reason="stat_anomaly",
                                path="",
                                features=feature_row
                            )

                        st.reset()

                    next_tick += WINDOW_S
                    continue

                # 로그 저장
                logger.write(ev)

                # 1. 먼저 PID별 통계 업데이트
                st = stats[ev.pid]
                st.update(ev)

                # 2. 그다음 Stage1 경량 탐지
                is_suspicious, reason = await stage1.check(ev)

                if is_suspicious:
                    feature_row = st.to_feature_row()

                    await ops.mark_suspect(
                        ev.pid,
                        reason=reason,
                        path=ev.path,
                        features=feature_row
                    )

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

        self._write_buffer: Dict[int, list] = defaultdict(list)
        self._write_count:  Dict[int, int]  = defaultdict(int)
        self._risk_score:   Dict[int, float] = {}

        self._staging_dir = "/tmp/guardfs_staging"
        os.makedirs(self._staging_dir, exist_ok=True)
        self._staging_fh:  Dict[int, str]  = {}
        self._staging_pid: Dict[int, list] = defaultdict(list)

        self._suspended_pids: set = set()
        self._high_reason: Dict[int, str] = {}
        self._pid_override_file = "/tmp/guardfs_pid_override.json"
        self._pid_features: Dict[int, dict] = {}  # Stage1이 보낸 최신 피처 저장

    # ------------------------------------------------------------------ helpers

    def _get_forced_state(self, pid: int) -> Optional[ProcState]:
        """override 파일 있으면 해당 상태, 없으면 None (실제 ML 탐지 모드)"""
        try:
            with open(f"/tmp/guardfs_state_{pid}", "r") as f:
                s = f.read().strip().upper()
            if s in ("LOW", "MEDIUM", "HIGH"):
                return ProcState(s)
        except Exception:
            pass
        return None

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

    async def mark_suspect(self, pid: int, reason: str = "", path: str = "", features=None) -> None:
        if pid <= 0:
            return

        # 최신 피처 항상 저장 (REEVAL에서 사용)
        if features:
            self._pid_features[pid] = features

        async with self._pid_lock:
            prev = self._proc_state.get(pid, ProcState.LOW)

            # HIGH면 재평가 불필요
            if prev == ProcState.HIGH:
                return

            # 상태 승격
            if prev == ProcState.LOW:
                self._proc_state[pid] = ProcState.SUSPICIOUS
                print(f"[STATE] pid={pid} LOW -> SUSPICIOUS reason={reason}")
            # MEDIUM이면 상태 유지 (피처만 업데이트됨)

            # 이미 큐에 올라간 PID면 중복 전송 방지
            if pid in self._queued_stage2:
                return

            self._queued_stage2.add(pid)

        await self._stage2_send.send({
            "pid": pid,
            "reason": reason,
            "path": path,
            "features": features,
            "ts": time.time()
        })

    async def get_proc_state(self, pid: int) -> ProcState: # pid의 현재 상태를 읽어오는 것
        if pid <= 0:
            return ProcState.LOW
        async with self._pid_lock:
            return self._proc_state.get(pid, ProcState.LOW)

    async def set_proc_state(self, pid: int, state: ProcState) -> None:  # pid의 상태를 바꾸는 것
        async with self._pid_lock:
            prev = self._proc_state.get(pid, ProcState.LOW) # 이전 상태 저장
            self._proc_state[pid] = state # 새 상태로 변경
            print(f"[STATE] pid={pid} {prev} → {state}")

    # 여기도 추가 (High 격상 트리거용) 
    async def trigger_high(self, pid: int, reason: str = "") -> None:
        print(f"[TRIGGER HIGH] pid={pid} reason={reason}")
        await self.set_proc_state(pid, ProcState.HIGH)
        from high import handle_high_enter
        await handle_high_enter(pid, self, reason)
    
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
        p = self._resolve_path(parent_inode, name)
        pid = ctx.pid if ctx is not None else -1

        override = self._get_forced_state(pid)
        if override is not None:
            await self.set_proc_state(pid, override)
            state = override
        else:
            state = await self.get_proc_state(pid)
            if state == ProcState.SUSPICIOUS:
                state = ProcState.LOW  # ML 결과 대기 중, 일단 통과

        if state in (ProcState.MEDIUM, ProcState.HIGH):
            staging_path = os.path.join(self._staging_dir, f"fh_{self._next_fh}")
            try:
                fd = os.open(staging_path, os.O_RDWR | os.O_CREAT | os.O_TRUNC, mode)
            except OSError as e:
                raise pyfuse3.FUSEError(e.errno)

            fh = self._next_fh
            self._next_fh += 1
            self._fd_map[fh] = fd
            self._fh_info[fh] = (pid, p, flags)
            self._staging_fh[fh] = staging_path
            self._staging_pid[pid].append(staging_path)
            self._emit(FsEvent(ts_ns=time.time_ns(), pid=pid, op="create", path=p, flags=flags))

            attr = pyfuse3.EntryAttributes()
            attr.st_ino = fh + 0x80000000
            attr.st_mode = stat_mod.S_IFREG | (mode & 0o7777)
            attr.st_nlink = 1
            attr.st_uid = ctx.uid if ctx is not None else os.getuid()
            attr.st_gid = ctx.gid if ctx is not None else os.getgid()
            attr.st_size = 0
            attr.st_blksize = 4096
            attr.st_blocks = 0
            ts = time.time_ns()
            attr.st_atime_ns = ts
            attr.st_mtime_ns = ts
            attr.st_ctime_ns = ts
            attr.entry_timeout = 1.0
            attr.attr_timeout = 1.0

            label = "스테이징 (underlay 미생성)" if state == ProcState.MEDIUM else "HIGH 차단 (underlay 미생성)"
            print(f"[CREATE] pid={pid} path={p} → {label}")

            fi = pyfuse3.FileInfo()
            fi.fh = fh
            return fi, attr

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
        ent = shannon_entropy(buf[:256])
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

        override = self._get_forced_state(pid)
        if override is not None:
            # override 파일 있음: 강제 상태 적용, ML 평가 없음
            await self.set_proc_state(pid, override)
            state = override
        else:
            # 실제 탐지 모드: Stage1 → mark_suspect → stage2 경로만 사용
            state = await self.get_proc_state(pid)
            if state == ProcState.SUSPICIOUS:
                state = ProcState.LOW  # ML 결과 대기 중, 일단 통과

        print(f"[WRITE] pid={pid} state={state} path={path}")

        if state == ProcState.HIGH:
            from high import handle_write_high
            return await handle_write_high(fd, off, buf, path, pid, self)

        elif state == ProcState.MEDIUM:
            from medium import handle_write_medium
            return await handle_write_medium(fd, off, buf, path, pid, self)

        else:
            from low import handle_write_low
            return await handle_write_low(fd, off, buf, path, pid, self)

    async def truncate(self, inode, size, ctx=None):
        p = self._inode_path.get(inode)
        if p is None:
            raise pyfuse3.FUSEError(errno.ENOENT)

        pid = ctx.pid if ctx is not None else -1

        if await self.get_proc_state(pid) == ProcState.HIGH:
            from high import handle_truncate_high
            await handle_truncate_high(p, size, pid, self)
            return

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

        if await self.get_proc_state(pid) == ProcState.HIGH:
            from high import handle_truncate_high
            await handle_truncate_high(path, size, pid, self)
            return

        try:
            os.ftruncate(fd, size)
        except OSError as e:
            raise pyfuse3.FUSEError(e.errno)

        self._emit(FsEvent(ts_ns=time.time_ns(), pid=pid, op="ftruncate", path=path, size=size))

    async def unlink(self, parent_inode, name, ctx=None):
        p = self._resolve_path(parent_inode, name)

        pid = ctx.pid if ctx is not None else -1

        if await self.get_proc_state(pid) == ProcState.HIGH:
            from high import handle_unlink_high
            await handle_unlink_high(p, pid, self)
            return

        try:
            os.unlink(p)
        except OSError as e:
            raise pyfuse3.FUSEError(e.errno)

        self._emit(FsEvent(ts_ns=time.time_ns(), pid=pid, op="unlink", path=p))

    async def rename(self, parent_inode_old, name_old, parent_inode_new, name_new, flags, ctx=None):
        oldp = self._resolve_path(parent_inode_old, name_old)
        newp = self._resolve_path(parent_inode_new, name_new)

        pid = ctx.pid if ctx is not None else -1

        if await self.get_proc_state(pid) == ProcState.HIGH:
            from high import handle_rename_high
            await handle_rename_high(oldp, newp, pid, self)
            return

        try:
            os.rename(oldp, newp)
        except OSError as e:
            raise pyfuse3.FUSEError(e.errno)

        self._emit(FsEvent(ts_ns=time.time_ns(), pid=pid, op="rename", path=oldp, new_path=newp))

    async def release(self, fh):
        pid, path, flags = self._fh_info.pop(fh, (-1, "?", 0))
        self._emit(FsEvent(ts_ns=time.time_ns(), pid=pid, op="release", path=path, flags=flags))

        fd = self._fd_map.pop(fh, None)
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

        staging_path = self._staging_fh.pop(fh, None)
        if staging_path:
            try:
                os.unlink(staging_path)
            except OSError:
                pass

class PidStats:
    FEATURE_COLS = [
        "O_sum", "C_sum", "D_sum", "E_sum",
        "Is_System_Path", "Is_Test_Path", "is_dev",
        "CCC", "CCD", "CCO", "CDC", "CDD", "CDO",
        "COC", "COD", "COO", "DCC", "DCD", "DCO",
        "DDC", "DDD", "DDO", "DOC", "DOD", "DOO",
        "EEE", "EEO", "EOE", "EOO", "OCC", "OCD",
        "OCO", "ODC", "ODD", "ODO", "OEE", "OOC",
        "OOD", "OOO"
    ]

    def __init__(self):
        self.counts = {col: 0 for col in self.FEATURE_COLS}
        self.seq = []   # 최근 O/C/D/E 이벤트 흐름 저장

    def reset(self) -> None:
        self.__init__()

    def mean_entropy(self) -> float:
        # 기존 stat_anomaly 조건에서 쓰이므로 임시 유지
        return float(self.counts["E_sum"])

    def _map_event(self, ev):
        """
        CSV feature 기준으로 이벤트를 O/C/D/E로 변환
        O = open/read/write 계열 파일 접근
        C = create/mkdir 계열 생성
        D = unlink/rmdir 계열 삭제
        E = entropy high write 또는 suspicious encryption-like event
        """
        if ev.op in ("create", "mkdir"):
            return "C"

        if ev.op in ("unlink", "rmdir"):
            return "D"

        if ev.op == "write" and ev.entropy is not None and ev.entropy >= 7.0:
            return "E"

        if ev.op in ("open", "read", "write", "lookup", "release", "rename"):
            return "O"

        return None

    def update(self, ev) -> None:
        code = self._map_event(ev)
        if code is None:
            return

        # 단일 이벤트 합계
        self.counts[f"{code}_sum"] += 1

        # 경로 기반 feature
        path = ev.path or ""

        if path.startswith("/usr") or path.startswith("/bin") or path.startswith("/sbin") or path.startswith("/etc"):
            self.counts["Is_System_Path"] = 1

        if "test" in path.lower() or "underlay" in path.lower() or "mnt" in path.lower():
            self.counts["Is_Test_Path"] = 1

        if "/dev/" in path:
            self.counts["is_dev"] = 1

        # 3-gram sequence feature
        self.seq.append(code)
        if len(self.seq) >= 3:
            tri = "".join(self.seq[-3:])
            if tri in self.counts:
                self.counts[tri] += 1

        # 너무 길어지지 않게 최근 100개만 유지
        if len(self.seq) > 100:
            self.seq = self.seq[-100:]

    def to_feature_row(self) -> dict:
        return {col: self.counts.get(col, 0) for col in self.FEATURE_COLS}

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
