#!/usr/bin/env python3

import argparse
import errno
import os
import stat as stat_mod
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

sys.path.insert(
    0,
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")),
)

import pyfuse3
import trio

from guardfs.common.config import (
    ENTROPY_HEADER_SIZE,
    ENTROPY_THRESHOLD,
    STATS_E_SUM_THRESHOLD,
    STATS_RENAME_THRESHOLD,
    STATS_UNLINK_THRESHOLD,
    STATS_WINDOW_SEC,
    STATS_WRITE_THRESHOLD,
)
from guardfs.common.paths import (
    PID_OVERRIDE_FILE,
    STAGING_DIR,
    get_collect_log_dir,
    get_event_log_path,
    get_forced_state_path,
    get_honeypot_dir,
)
from guardfs.collect.fuse_logger import (
    RUN_ID_PATTERN,
    FuseCollectLogger,
    new_run_id,
)
from guardfs.stage1.detector import Stage1Detector
from guardfs.stage1.entropy import shannon_entropy
from guardfs.stage1.logger import EventLogger
from guardfs.stage2.stage2_worker import stage2_worker
from guardfs.stage2.states import ProcState

def _full_path(root: str, path: str) -> str:
    if path.startswith("/"):
        path = path[1:]
    return os.path.join(root, path)

@dataclass
class FsEvent:
    """통계 수집기 및 Stage 1 탐지기에 전달하는 파일 시스템 이벤트이다."""
    
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
    이벤트를 기록하고 PID별 통계 및 Stage 1 탐지를 수행한다.
    - EventLogger   : 모든 이벤트를 JSONL로 저장
    - PidStats      : PID별 최근 행동 통계 집계
    - Stage1Detector: 경량 탐지 수행
    """

    stats = defaultdict(PidStats)
    logger = EventLogger(log_path)
    stage1 = Stage1Detector(honeypot_dir)

    next_tick = trio.current_time() + STATS_WINDOW_SEC

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
                            (
                            st.counts["W_sum"] >= STATS_WRITE_THRESHOLD
                             and mean_ent >= STATS_E_SUM_THRESHOLD
                            )
                            or (
                            st.counts["D_sum"] >= STATS_RENAME_THRESHOLD
                            )
                            or (
                            st.counts["D_sum"] >= STATS_UNLINK_THRESHOLD
                            )
                        )

                        if suspicious and pid > 0:
                            feature_row = st.to_feature_row()

                            print(
                                f"[SUSPICIOUS] pid={pid} "
                                f"W_sum={st.counts['W_sum']} "
                                f"E_sum={mean_ent:.0f} "
                                f"D_sum={st.counts['D_sum']}"
                            )

                            await ops.mark_suspect(
                                pid,
                                reason="stat_anomaly",
                                path="",
                                features=feature_row
                            )

                        st.reset()

                    next_tick += STATS_WINDOW_SEC
                    continue

                # 동일 이벤트를 로그, 통계, Stage 1(경량) 순서로 처리
                logger.write(ev)

                st = stats[ev.pid]
                st.update(ev)

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
    """underlay에 파일 연산을 전달하고 탐지 상태에 따라 정책을 적용한다."""
    
    def __init__(self, root: str, collect_logger: Optional[FuseCollectLogger] = None):
        super().__init__()
        self.root = os.path.realpath(root)

        # 수집 모드: 탐지·차단 정책 없이 모든 이벤트를 collect_logger에 기록한다.
        self._collect = collect_logger

        self._inode_path: Dict[int, str] = {
            pyfuse3.ROOT_INODE: self.root
        }
        self._fd_map: Dict[int, int] = {}
        self._next_fh = 1

        self._fh_info: Dict[int, Tuple[int, str, int]] = {}

        # opendir에서 발급한 fh → 해당 디렉토리 경로 매핑
        self._dir_fh_path: Dict[int, str] = {}

        self._send_chan, self._recv_chan = trio.open_memory_channel(10000)
        self._stage2_send, self._stage2_recv = trio.open_memory_channel(1000)

        # 로그 파일을 underlay 바깥(프로젝트 루트)에 저장
        self._log_path = get_event_log_path(self.root)

        self._pid_lock = trio.Lock()

        # PID 상태 관리
        self._proc_state: Dict[int, ProcState] = {}

        # Stage2 큐 중복 등록 방지
        self._queued_stage2: set[int] = set()

        self._write_buffer: Dict[int, list] = defaultdict(list)
        self._write_count:  Dict[int, int]  = defaultdict(int)
        self._risk_score:   Dict[int, float] = {}

        # MEDIUM/HIGH create 시 사용할 staging 영역
        self._staging_dir = STAGING_DIR
        os.makedirs(self._staging_dir, exist_ok=True)
        
        self._staging_fh:  Dict[int, str]  = {}
        self._staging_pid: Dict[int, list] = defaultdict(list)

        self._suspended_pids: set = set()
        self._high_reason: Dict[int, str] = {}
        self._pid_override_file = PID_OVERRIDE_FILE
        
        # Stage1이 전달한 최신 feature
        self._pid_features: Dict[int, dict] = {}
        
        # PID → 실행파일 경로. 정적 모델이 /proc/<pid>/exe 를 못 읽는
        # 단명 프로세스를 위한 폴백용이다. (PID당 1회만 조회)
        self._pid_exe: Dict[int, str] = {}

    # ---------------------------------- helpers ---------------------------------- #

    def _get_forced_state(self, pid: int) -> Optional[ProcState]:
        """override 파일 있으면 해당 상태, 없으면 None (실제 ML 탐지 모드)"""

        if self._collect is not None:
            return None

        try:
            with open(get_forced_state_path(pid), "r") as f:
                s = f.read().strip().upper()
                
            if s in ("LOW", "MEDIUM", "HIGH"):
                return ProcState(s)
            
        except (FileNotFoundError, OSError):
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
        # 수집 모드는 채널을 거치지 않고 동기 기록한다. 채널이 가득 차면
        # 이벤트가 버려지는데, 수집 데이터에서는 유실이 허용되지 않는다.
        if self._collect is not None:
            self._collect.write(ev)
            return

        # 프로세스가 살아있는 동안(= 이벤트 발생 시점) 한 번만 조회해 캐싱한다.
        # Stage2가 평가하는 시점에는 이미 종료돼 읽지 못하는 경우가 많다.
        if ev.pid > 0 and ev.pid not in self._pid_exe:
            try:
                self._pid_exe[ev.pid] = os.readlink(f"/proc/{ev.pid}/exe")
            except OSError:
                self._pid_exe[ev.pid] = ""

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

    async def get_proc_state(self, pid: int) -> ProcState:
        """PID의 현재 상태를 반환한다."""
        
        if pid <= 0:
            return ProcState.LOW
        async with self._pid_lock:
            return self._proc_state.get(pid, ProcState.LOW)


    async def set_proc_state(self, pid: int, state: ProcState) -> None:
        """PID의 GuardFS 상태를 변경한다."""
        
        async with self._pid_lock:
            prev = self._proc_state.get(pid, ProcState.LOW) # 이전 상태 저장
            self._proc_state[pid] = state # 새 상태로 변경
            
            print(f"[STATE] pid={pid} {prev} → {state}")


    async def trigger_high(self, pid: int, reason: str = "") -> None:
        print(f"[TRIGGER HIGH] pid={pid} reason={reason}")
        
        await self.set_proc_state(pid, ProcState.HIGH)
        from guardfs.stage2.policy.high import handle_high_enter
        await handle_high_enter(pid, self, reason)

    def _find_open_fd_for_path(self, path: str) -> Optional[int]:
        """열린 fd 검색 helper"""
        for fh, (_pid, fh_path, _flags) in self._fh_info.items():
            if fh_path != path:
                continue

            fd = self._fd_map.get(fh)

            if fd is not None:
                return fd

        return None
    
    # ---------------------------------- FUSE ops ---------------------------------- #

    async def access(self, inode, mode, ctx=None):
        # pyfuse3는 반환값이 참일 때만 허용한다. None이면 chdir/access(2)가 EACCES로 실패한다.
        return True


    async def getattr(self, inode, ctx=None):
        p = self._inode_path.get(inode)
        
        if p is None:
            raise pyfuse3.FUSEError(errno.ENOENT)
        
        try:
            st = os.lstat(p)

        except FileNotFoundError:
            fd = self._find_open_fd_for_path(p)

            if fd is None:
                raise pyfuse3.FUSEError(errno.ENOENT)

            try:
                st = os.fstat(fd)
            except OSError as e:
                raise pyfuse3.FUSEError(e.errno)

        except OSError as e:
            raise pyfuse3.FUSEError(e.errno)
        
        return self._stat_to_attr(st)


    async def lookup(self, parent_inode, name, ctx=None):
        # ROOT_INODE 고정 → parent_inode 기반 경로 조합
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
        p = self._resolve_path(parent_inode, name)
        pid = ctx.pid if ctx is not None else -1

        override = self._get_forced_state(pid)

        if override is not None:
            await self.set_proc_state(pid, override)
            state = override
        else:
            state = await self.get_proc_state(pid)

            if state == ProcState.SUSPICIOUS:
                state = ProcState.LOW

        if state == ProcState.HIGH:
            from guardfs.stage2.policy.high import handle_mkdir_high

            await handle_mkdir_high(
                path=p,
                pid=pid,
                ops=self,
            )

            raise pyfuse3.FUSEError(errno.EACCES)

        try:
            os.mkdir(p, mode)
        except OSError as e:
            raise pyfuse3.FUSEError(e.errno)

        st = self._register_inode(p)

        self._emit(
            FsEvent(
                ts_ns=time.time_ns(),
                pid=pid,
                op="mkdir",
                path=p,
            )
        )

        return self._stat_to_attr(st)


    async def rmdir(self, parent_inode, name, ctx=None):
        p = self._resolve_path(parent_inode, name)
        pid = ctx.pid if ctx is not None else -1

        override = self._get_forced_state(pid)

        if override is not None:
            await self.set_proc_state(pid, override)
            state = override
        else:
            state = await self.get_proc_state(pid)

            if state == ProcState.SUSPICIOUS:
                state = ProcState.LOW

        if state == ProcState.HIGH:
            from guardfs.stage2.policy.high import handle_rmdir_high

            await handle_rmdir_high(
                path=p,
                pid=pid,
                ops=self,
            )

            raise pyfuse3.FUSEError(errno.EACCES)

        try:
            os.rmdir(p)
        except OSError as e:
            raise pyfuse3.FUSEError(e.errno)

        self._emit(
            FsEvent(
                ts_ns=time.time_ns(),
                pid=pid,
                op="rmdir",
                path=p,
            )
        )


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
        # fh == 1 고정 → fh로 경로 조회
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
        # opendir에서 발급한 fh 정리
        self._dir_fh_path.pop(fh, None)


    async def open(self, inode, flags, ctx=None):
        p = self._inode_path.get(inode)
        
        if p is None:
            raise pyfuse3.FUSEError(errno.ENOENT)

        # os.open() 전에 요청 PID 확인
        pid = ctx.pid if ctx is not None else -1

        override = self._get_forced_state(pid)

        if override is not None:
            await self.set_proc_state(pid, override)
            state = override
        else:
            state = await self.get_proc_state(pid)

            if state == ProcState.SUSPICIOUS:
                state = ProcState.LOW

        # O_TRUNC는 os.open() 순간 원본 파일을 비우므로 사전 차단
        if state == ProcState.HIGH and flags & os.O_TRUNC:
            from guardfs.stage2.policy.high import (
                handle_open_trunc_high,
            )

            await handle_open_trunc_high(
                path=p,
                flags=flags,
                pid=pid,
                ops=self,
            )

            raise pyfuse3.FUSEError(errno.EACCES)

        try:
            fd = os.open(p, flags)
        except OSError as e:
            raise pyfuse3.FUSEError(e.errno)

        fh = self._next_fh
        self._next_fh += 1

        self._fd_map[fh] = fd
        self._fh_info[fh] = (pid, p, flags)

        self._emit(
            FsEvent(
                ts_ns=time.time_ns(),
                pid=pid,
                op="open",
                path=p,
                flags=flags,
            )
        )

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
        ent = shannon_entropy(buf[:ENTROPY_HEADER_SIZE])
        
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
            from guardfs.stage2.policy.high import handle_write_high
            return await handle_write_high(fd, off, buf, path, pid, self)

        elif state == ProcState.MEDIUM:
            from guardfs.stage2.policy.medium import handle_write_medium
            return await handle_write_medium(fd, off, buf, path, pid, self)

        else:
            from guardfs.stage2.policy.low import handle_write_low
            return await handle_write_low(fd, off, buf, path, pid, self)
    
    async def setattr(
        self,
        inode,
        attr,
        fields,
        fh,
        ctx=None,
    ):
        if fields.update_size:
            if fh is None:
                await self.truncate(
                    inode,
                    attr.st_size,
                    ctx,
                )
            else:
                await self.ftruncate(
                    fh,
                    attr.st_size,
                )

        if (
            fields.update_mode
            or fields.update_uid
            or fields.update_gid
            or fields.update_atime
            or fields.update_mtime
        ):
            await self._set_metadata(inode, attr, fields, ctx)

        return await self.getattr(inode, ctx)

    async def _set_metadata(self, inode, attr, fields, ctx=None):
        """chmod / chown / utimens. ctime은 커널이 갱신하므로 따로 설정하지 않는다."""
        p = self._inode_path.get(inode)

        if p is None:
            raise pyfuse3.FUSEError(errno.ENOENT)

        pid = ctx.pid if ctx is not None else -1

        if await self.get_proc_state(pid) == ProcState.HIGH:
            from guardfs.stage2.policy.high import handle_setattr_high

            if fields.update_mode:
                await handle_setattr_high(p, f"CHMOD(mode={stat_mod.S_IMODE(attr.st_mode):o})", pid, self)
            if fields.update_uid or fields.update_gid:
                await handle_setattr_high(p, "CHOWN", pid, self)
            if fields.update_atime or fields.update_mtime:
                await handle_setattr_high(p, "UTIME", pid, self)
            return

        try:
            if fields.update_mode:
                os.chmod(p, stat_mod.S_IMODE(attr.st_mode))

            if fields.update_uid or fields.update_gid:
                os.chown(
                    p,
                    attr.st_uid if fields.update_uid else -1,
                    attr.st_gid if fields.update_gid else -1,
                    follow_symlinks=False,
                )

            if fields.update_atime or fields.update_mtime:
                st = os.lstat(p)
                os.utime(
                    p,
                    ns=(
                        attr.st_atime_ns if fields.update_atime else st.st_atime_ns,
                        attr.st_mtime_ns if fields.update_mtime else st.st_mtime_ns,
                    ),
                    follow_symlinks=False,
                )
        except OSError as e:
            raise pyfuse3.FUSEError(e.errno)

        if fields.update_mode:
            self._emit(FsEvent(ts_ns=time.time_ns(), pid=pid, op="chmod", path=p,
                               flags=stat_mod.S_IMODE(attr.st_mode)))
        if fields.update_uid or fields.update_gid:
            self._emit(FsEvent(ts_ns=time.time_ns(), pid=pid, op="chown", path=p))
        if fields.update_atime or fields.update_mtime:
            self._emit(FsEvent(ts_ns=time.time_ns(), pid=pid, op="utime", path=p))


    async def truncate(self, inode, size, ctx=None):
        p = self._inode_path.get(inode)
        
        if p is None:
            raise pyfuse3.FUSEError(errno.ENOENT)

        pid = ctx.pid if ctx is not None else -1

        if await self.get_proc_state(pid) == ProcState.HIGH:
            from guardfs.stage2.policy.high import handle_truncate_high
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
            from guardfs.stage2.policy.high import handle_truncate_high
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
            from guardfs.stage2.policy.high import handle_unlink_high
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
            from guardfs.stage2.policy.high import handle_rename_high

            await handle_rename_high(oldp, newp, pid, self)
            return

        try:
            os.rename(oldp, newp)
        except OSError as e:
            raise pyfuse3.FUSEError(e.errno)

        old_prefix = oldp + os.sep
        new_prefix = newp + os.sep

        moved_inodes = {
            inode
            for inode, path in self._inode_path.items()
            if path == oldp or path.startswith(old_prefix)
        }

        for inode, path in list(self._inode_path.items()):
            if inode not in moved_inodes and (
                path == newp or path.startswith(new_prefix)
            ):
                self._inode_path.pop(inode, None)

        for inode in moved_inodes:
            path = self._inode_path[inode]
            self._inode_path[inode] = newp + path[len(oldp):]

        for fh, (fh_pid, path, fh_flags) in list(self._fh_info.items()):
            if path == oldp or path.startswith(old_prefix):
                self._fh_info[fh] = (
                    fh_pid,
                    newp + path[len(oldp):],
                    fh_flags,
                )

        for fh, path in list(self._dir_fh_path.items()):
            if path == oldp or path.startswith(old_prefix):
                self._dir_fh_path[fh] = newp + path[len(oldp):]

        self._emit(
            FsEvent(
                ts_ns=time.time_ns(),
                pid=pid,
                op="rename",
                path=oldp,
                new_path=newp,
            )
        )

    async def release(self, fh):
        pid, path, flags = self._fh_info.pop(fh, (-1, "?", 0))
        fd = self._fd_map.pop(fh, None)

        inode = None

        if fd is not None:
            try:
                inode = os.fstat(fd).st_ino
            except OSError:
                pass

            try:
                os.close(fd)
            except OSError:
                pass

        if inode is not None and not os.path.exists(path):
            still_open = False

            for other_fh in self._fh_info:
                other_fd = self._fd_map.get(other_fh)

                if other_fd is None:
                    continue

                try:
                    if os.fstat(other_fd).st_ino == inode:
                        still_open = True
                        break
                except OSError:
                    continue

            if not still_open and self._inode_path.get(inode) == path:
                self._inode_path.pop(inode, None)

        self._emit(
            FsEvent(
                ts_ns=time.time_ns(),
                pid=pid,
                op="release",
                path=path,
                flags=flags,
            )
        )

        staging_path = self._staging_fh.pop(fh, None)

        if staging_path:
            try:
                os.unlink(staging_path)
            except OSError:
                pass

class PidStats:
    # 동적 모델 v2(rf_model_v2.pkl)의 입력 피처. 순서/내용이
    # models/dynamic/feature_cols_v2.json 과 반드시 일치해야 한다.
    FEATURE_COLS = [
        "O_sum", "C_sum", "D_sum", "W_sum",
        "CCC", "CCD", "CCO", "CDC", "CDD", "CDO",
        "COC", "COD", "COO", "DCC", "DCD", "DCO",
        "DDC", "DDD", "DDO", "DOC", "DOD", "DOO",
        "OCC", "OCD", "OCO", "ODC", "ODD", "ODO",
        "OOC", "OOD", "OOO",
        "WCC", "WCD", "WCO", "WCW", "WDC", "WDD",
        "WDO", "WDW", "WOC", "WOD", "WOO", "WOW",
        "WWC", "WWD", "WWO", "WWW",
        "CWC", "CWD", "CWO", "CWW", "DWC", "DWD",
        "DWO", "DWW", "OWC", "OWD", "OWO", "OWW",
        "CCW", "CDW", "COW", "DCW", "DDW", "DOW",
        "OCW", "ODW", "OOW",
    ]

    def __init__(self):
        # 1초 윈도우 카운터. stats_collector의 stat_anomaly 게이트 전용이며
        # 매 윈도우마다 reset()으로 초기화된다.
        self.counts = {col: 0 for col in self.FEATURE_COLS}

        # 프로세스 생애 누적 카운터. ML 입력 전용이며 reset()에서 유지된다.
        # 학습 데이터(dataset_v2_4th_clean.csv)가 프로세스 단위 누적
        # 집계이므로, 추론도 동일하게 누적값을 넣어야 분포가 맞는다.
        self.total = {col: 0 for col in self.FEATURE_COLS}

        # 이벤트 흐름. 3-gram이 윈도우 경계에서 끊기지 않도록 reset()에서 유지한다.
        self.seq = []

        # 고엔트로피 write 누적. ML 피처가 아니라 Stage1 게이트 전용이므로
        # 윈도우 단위로 초기화된다. (모델 v2는 엔트로피를 피처로 쓰지 않음)
        self.e_sum = 0

    def reset(self) -> None:
        """1초 윈도우 종료 시 호출. 게이트용 카운터만 초기화한다."""
        self.counts = {col: 0 for col in self.FEATURE_COLS}
        self.e_sum = 0

    def mean_entropy(self) -> float:
        # stats_collector의 stat_anomaly 게이트에서 사용.
        # W_sum이 아니라 반드시 고엔트로피 write 카운트를 반환해야 한다.
        return float(self.e_sum)

    def _map_event(self, ev):
        """
        이벤트를 모델 v2의 O/C/D/W 코드로 변환한다.
        O = open/read/lookup/release/rename 계열 접근
        C = create/mkdir 계열 생성
        D = unlink/rmdir 계열 삭제
        W = write (엔트로피와 무관하게 전부 W)
        """
        if ev.op in ("create", "mkdir"):
            return "C"

        if ev.op in ("unlink", "rmdir"):
            return "D"

        if ev.op == "write":
            return "W"

        if ev.op in ("open", "read", "lookup", "release", "rename"):
            return "O"

        return None

    def update(self, ev) -> None:
        code = self._map_event(ev)

        if code is None:
            return

        # 게이트 전용 엔트로피 카운터 (ML 피처와 무관)
        if (
            code == "W"
            and ev.entropy is not None
            and ev.entropy >= ENTROPY_THRESHOLD
        ):
            self.e_sum += 1

        # 단일 이벤트 합계 (윈도우 + 누적)
        key = f"{code}_sum"
        self.counts[key] += 1
        self.total[key] += 1

        # 3-gram sequence feature
        self.seq.append(code)

        if len(self.seq) >= 3:
            tri = "".join(self.seq[-3:])

            if tri in self.counts:
                self.counts[tri] += 1
                self.total[tri] += 1

        # 최근 100개 이벤트만 유지
        if len(self.seq) > 100:
            self.seq = self.seq[-100:]

    def to_feature_row(self) -> dict:
        """
        ML 입력 행. 학습 데이터와 동일하게 생애 누적값을 반환한다.
        (게이트가 참조하는 self.counts 와 혼동하지 말 것)
        """
        return {
            col: self.total.get(col, 0)
            for col in self.FEATURE_COLS
        }
        
async def main(
    mountpoint: str,
    root: str,
    collect_logger: Optional[FuseCollectLogger] = None,
):
    honeypot_dir = get_honeypot_dir(root)

    ops = Passthrough(root, collect_logger)

    pyfuse3.init(
        ops,
        mountpoint,
        set()
    )

    try:
        async with trio.open_nursery() as nursery:
            # 수집 모드에서는 Stage 1 판정과 Stage 2(ML·정책)를 띄우지 않는다.
            # 차단이 걸리면 샘플이 끝까지 실행되지 않아 로그가 불완전해진다.
            if collect_logger is None:
                nursery.start_soon(
                    stats_collector,
                    ops._recv_chan,
                    ops._log_path,
                    honeypot_dir,
                    ops,
                )

                nursery.start_soon(
                    stage2_worker,
                    ops._stage2_recv,
                    ops
                )

            await pyfuse3.main()

    finally:
        pyfuse3.close(unmount=True)


def _run_id_arg(value: str) -> str:
    if not RUN_ID_PATTERN.match(value):
        raise argparse.ArgumentTypeError("영문, 숫자, '.', '_', '-'만 사용할 수 있습니다")
    return value


def parse_args():
    parser = argparse.ArgumentParser(description="GuardFS FUSE passthrough")
    parser.add_argument("mountpoint")
    parser.add_argument("underlay")
    parser.add_argument(
        "--collect-only",
        action="store_true",
        help="탐지·차단 정책 없이 파일 이벤트만 기록하는 데이터 수집 모드",
    )
    parser.add_argument(
        "--run-id",
        type=_run_id_arg,
        help="수집 세션 ID (--collect-only 전용, 생략 시 자동 생성)",
    )

    args = parser.parse_args()

    if args.run_id and not args.collect_only:
        parser.error("--run-id는 --collect-only와 함께 사용해야 합니다")

    return args


if __name__ == "__main__":
    args = parse_args()

    collect_logger = None

    if args.collect_only:
        collect_logger = FuseCollectLogger(
            get_collect_log_dir(args.underlay),
            args.run_id or new_run_id(),
            args.mountpoint,
            args.underlay,
        )
        print(f"[COLLECT] run_id={collect_logger.run_id} log={collect_logger.log_path}")

    try:
        trio.run(main, args.mountpoint, args.underlay, collect_logger)
    finally:
        if collect_logger is not None:
            collect_logger.close()
