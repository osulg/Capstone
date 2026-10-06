#!/usr/bin/env python3

import argparse
import errno
import os
import random
import re
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

from guardfs.collect.fuse_logger import (
    RUN_ID_PATTERN,
    FuseCollectLogger,
    new_run_id,
)
from guardfs.common.config import (
    ENTROPY_MAX_EVENT_SAMPLE_SIZE,
    ENTROPY_SHORT_SAMPLE_THRESHOLD,
    ENTROPY_THRESHOLD,
    INTERPRETER_BASENAMES,
    STAGE1_SAMPLING_RATE,
    STATS_E_SUM_THRESHOLD,
    STATS_RENAME_THRESHOLD,
    STATS_UNLINK_THRESHOLD,
    STATS_WINDOW_SEC,
    STATS_WRITE_THRESHOLD,
    TRUSTED_EXE_PREFIXES,
)
from guardfs.common.paths import (
    PID_OVERRIDE_FILE,
    STAGING_DIR,
    get_collect_log_dir,
    get_event_log_path,
    get_forced_state_path,
    get_honeypot_dir,
)
from guardfs.stage1.detector import Stage1Detector
from guardfs.stage1.logger import EventLogger
from guardfs.stage1.trust import is_trusted_pid
from guardfs.stage2.stage2_worker import stage2_worker
from guardfs.stage2.states import ProcState


def _full_path(root: str, path: str) -> str:
    if path.startswith("/"):
        path = path[1:]
    return os.path.join(root, path)


def _resolve_trust_target(pid: int) -> str:
    """
    신뢰 판단 대상 경로를 계산한다.
    exe가 python/bash 등 인터프리터면 exe 자신이 아니라
    cmdline에서 실제로 실행 중인 스크립트 경로를 반환한다.
    (그렇지 않으면 /usr/bin/python3로 실행되는 임의의 스크립트가
    전부 "신뢰 경로"로 오분류된다.)
    """
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return ""

    basename = re.sub(r"[\d.]+$", "", os.path.basename(exe))

    if basename not in INTERPRETER_BASENAMES:
        return exe

    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read()
    except OSError:
        return ""

    args = [a.decode("utf-8", "surrogateescape") for a in raw.split(b"\x00") if a]

    for arg in args[1:]:
        if arg.startswith("-"):
            continue
        return os.path.abspath(arg)

    return ""


@dataclass
class FsEvent:
    """통계 수집기 및 Stage 1 탐지기에 전달하는 파일 시스템 이벤트이다"""

    ts_ns: int
    pid: int
    op: str
    path: str
    size: int = 0
    off: int = -1
    flags: int = 0
    entropy: Optional[float] = None
    new_path: Optional[str] = None
    sample_data: Optional[bytes] = None
    original_data: Optional[bytes] = None
    entropy_before: Optional[float] = None
    entropy_after: Optional[float] = None
    entropy_delta: Optional[float] = None
    applied: bool = True


async def stats_collector(
    recv_chan: trio.MemoryReceiveChannel,
    log_path: str,
    stage1: Stage1Detector,
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
                                st.w_win >= STATS_WRITE_THRESHOLD
                                and mean_ent >= STATS_E_SUM_THRESHOLD
                            )
                            or (st.d_win >= STATS_RENAME_THRESHOLD)
                            or (st.d_win >= STATS_UNLINK_THRESHOLD)
                        )

                        if suspicious and pid > 0:
                            feature_row = st.to_feature_row()

                            print(
                                f"[SUSPICIOUS] pid={pid} "
                                f"W_win={st.w_win} "
                                f"E_sum={mean_ent:.0f} "
                                f"D_win={st.d_win}"
                            )

                            await ops.mark_suspect(
                                pid,
                                reason="stat_anomaly",
                                path="",
                                features=feature_row,
                            )

                        st.reset()

                    next_tick += STATS_WINDOW_SEC
                    continue

                # 엔트로피는 _emit()에서 이미 계산함 상태
                # 여기서는 계산 결과를 재사용하여 탐지 판단만 수행
                is_suspicious, reason = await stage1.check(
                    ev,
                    entropy_suspicious=getattr(ev, "_entropy_suspicious", None),
                )

                # Stage 1에서 갱신된 이벤트를 로그와 PID 통계에 반영
                logger.write(ev)

                st = stats[ev.pid]
                st.update(ev)

                # 탐지 여부와 관계없이 재평가용 최신 피처를 저장
                if ev.pid > 0:
                    ops._pid_features[ev.pid] = st.to_feature_row()

                # 보조 샘플링 게이트: 신규 PID + 비신뢰 실행 경로면
                # Stage1 탐지기 결과와 무관하게 일정 확률로 강제 Stage2 등록.
                # PID당 최초 이벤트에서 단 한 번만 굴린다.
                if ev.pid > 0 and ev.pid not in ops._pid_sampled:
                    ops._pid_sampled.add(ev.pid)

                    if (
                        not ops.is_trusted_process(ev.pid)
                        and random.random() < STAGE1_SAMPLING_RATE
                    ):
                        print(
                            f"[STAGE1-SAMPLING] pid={ev.pid} path={ev.path} "
                            f"비신뢰 경로 신규 프로세스 → 강제 Stage2 등록"
                        )

                        await ops.mark_suspect(
                            ev.pid,
                            reason="stage1_sampling",
                            path=ev.path,
                            features=st.to_feature_row(),
                        )

                if is_suspicious:
                    feature_row = st.to_feature_row()

                    await ops.mark_suspect(
                        ev.pid, reason=reason, path=ev.path, features=feature_row
                    )

    finally:
        logger.close()


class Passthrough(pyfuse3.Operations):
    """underlay에 파일 연산을 전달하고 탐지 상태에 따라 정책을 적용한다."""

    def __init__(
        self,
        root: str,
        stage1: Stage1Detector,
        collect_logger: Optional[FuseCollectLogger] = None,
    ):
        super().__init__()

        self.root = os.path.realpath(root)
        self._stage1 = stage1
        self._collect = collect_logger

        self._inode_path: Dict[int, str] = {pyfuse3.ROOT_INODE: self.root}
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
        self._write_buffer_bytes: Dict[int, int] = defaultdict(int)

        # MEDIUM 진입 시각 (경과시간 기반 지연 계산용, PID당 1회만 기록)
        self._medium_entered_at: Dict[int, float] = {}

        # 전체 PID를 통틀어 현재 버퍼링 중인 총 바이트 수 (규칙5: 전역 상한)
        self._global_buffer_bytes: int = 0
        self._risk_score: Dict[int, float] = {}

        self._medium_pids: Dict[int, float] = {}

        # MEDIUM/HIGH create 시 사용할 staging 영역
        self._staging_dir = STAGING_DIR
        os.makedirs(self._staging_dir, exist_ok=True)

        self._staging_fh: Dict[int, str] = {}
        self._staging_pid: Dict[int, list] = defaultdict(list)

        self._suspended_pids: set = set()
        self._high_reason: Dict[int, str] = {}
        self._pid_override_file = PID_OVERRIDE_FILE

        # Stage1이 전달한 최신 feature
        self._pid_features: Dict[int, dict] = {}

        # PID → 실행파일 경로. 정적 모델이 /proc/<pid>/exe 를 못 읽는
        # 단명 프로세스를 위한 폴백용이다. (PID당 1회만 조회)
        self._pid_exe: Dict[int, str] = {}

        # MEDIUM 진입 시 계산 후 캐싱하는 프로세스 신뢰도
        self._pid_trusted: Dict[int, bool] = {}

        # Stage1 보조 샘플링을 이미 굴린 PID (PID당 1회만 시도)
        self._pid_sampled: set = set()

        # O_TRUNC로 열렸으나 실제로는 스테이징으로 유도된 (pid, path) 집합.
        # 커밋 시 이 경로는 기존 내용을 먼저 비우고 버퍼를 적용해야 한다.
        self._trunc_paths: Dict[int, set] = defaultdict(set)

        # MEDIUM 중 unlink를 실제로 지우지 않고 스테이징으로 옮겨둔 목록.
        # (원래_경로, 스테이징_경로) 튜플의 리스트 — 규칙4: 단계적 삭제 차단.
        self._unlink_staged: Dict[int, list] = defaultdict(list)

    # ---------------------------------- helpers ---------------------------------- #

    def is_trusted_process(self, pid: int) -> bool:
        """
        프로세스가 신뢰 경로(/bin, /usr/bin 등)에서 실행 중인지 반환한다.
        PID당 한 번만 계산하고 캐싱한다 (매 write마다 /proc 재조회 방지).
        """
        if pid in self._pid_trusted:
            return self._pid_trusted[pid]

        target = _resolve_trust_target(pid)
        trusted = bool(target) and target.startswith(TRUSTED_EXE_PREFIXES)
        self._pid_trusted[pid] = trusted

        return trusted

    def _resolve_suspicious_state(self, pid: int) -> ProcState:
        """
        SUSPICIOUS(ML 판정 대기 중)일 때 write/create/open을 어떻게 취급할지 결정한다.
        - 신뢰 경로: 기존과 동일하게 LOW로 취급하고 즉시 통과시킨다.
        - 비신뢰 경로: MEDIUM으로 취급해서 판정이 나올 때까지 선제적으로
          버퍼링/지연을 적용한다 (판정 전 첫 write가 무방비로 반영되는 것을 방지).
        """
        return ProcState.LOW if self.is_trusted_process(pid) else ProcState.MEDIUM

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
        # 수집·탐지 모드가 동일한 생명주기 및 엔트로피 계산을 사용
        self._stage1.update_lifecycle(ev)
        ev._entropy_suspicious = self._stage1.entropy.check(ev)

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

    async def mark_suspect(
        self, pid: int, reason: str = "", path: str = "", features=None
    ) -> None:
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

        await self._stage2_send.send(
            {
                "pid": pid,
                "reason": reason,
                "path": path,
                "features": features,
                "ts": time.time(),
            }
        )

    async def get_proc_state(self, pid: int) -> ProcState:
        """PID의 현재 상태를 반환한다."""

        if self._collect is not None:
            return ProcState.LOW

        if pid <= 0:
            return ProcState.LOW

        async with self._pid_lock:
            return self._proc_state.get(pid, ProcState.LOW)

    async def set_proc_state(
        self,
        pid: int,
        state: ProcState,
        *,
        preserve_high: bool = False,
        register_medium: bool = False,
    ) -> bool:
        """PID의 GuardFS 상태를 변경하고 상태 변경 성공 여부를 반환한다."""

        async with self._pid_lock:
            prev = self._proc_state.get(pid, ProcState.LOW)  # 이전 상태 저장

            if preserve_high and prev == ProcState.HIGH:
                return False

            self._proc_state[pid] = state  # 새 상태로 변경

            if state in (ProcState.HIGH, ProcState.LOW):
                self._medium_pids.pop(pid, None)

            elif state == ProcState.MEDIUM and register_medium:
                # 상태 변경과 재평가 등록을 같은 잠금에서 처리
                self._medium_pids.setdefault(pid, trio.current_time())

            print(f"[STATE] pid={pid} {prev} → {state}")

            return True

    async def trigger_high(self, pid: int, reason: str = "") -> None:
        print(f"[TRIGGER HIGH] pid={pid} reason={reason}")

        await self.set_proc_state(pid, ProcState.HIGH)
        from guardfs.stage2.policy.high import handle_high_enter

        await handle_high_enter(pid, self, reason)

    async def _resolve_effective_state(self, pid: int) -> ProcState:
        """
        호출 시점의 '실제 적용 상태'를 계산한다.

        순서:
        1. override 파일이 있으면 그걸 그대로 사용 (테스트/시뮬레이션용)
        2. SUSPICIOUS는 LOW로 취급 (Stage2 ML 결과 대기 중이므로 일단 통과)
        3. HIGH는 그대로 반환 (재평가 불필요)
        4. 신뢰도 낮은 PID(exe 경로 + 부모 프로세스 + 패키지 무결성 기준)는
           상태(LOW/SUSPICIOUS)와 무관하게 최소 MEDIUM으로 강제 승격
           → 랜섬웨어의 '진짜 첫 write'가 Stage1 판정 이전에
             underlay로 바로 반영되는 문제를 원천 차단

        MEDIUM으로 강제 승격된 PID는 self._medium_pids에 시각을 기록해서
        stage2_worker.py의 REEVAL 루프(10초 타임아웃, HIGH 격상 등)가
        동일하게 적용되도록 한다.
        """

        # 수집 모드는 신뢰도 gate와 staging 정책을 적용하지 않음
        if self._collect is not None:
            return ProcState.LOW

        override = self._get_forced_state(pid)

        if override is not None:
            await self.set_proc_state(pid, override)
            return override

        state = await self.get_proc_state(pid)
        if state == ProcState.SUSPICIOUS:
            state = self._resolve_suspicious_state(pid)

        if state == ProcState.HIGH:
            return state

        if state != ProcState.MEDIUM and not await is_trusted_pid(pid):
            changed = await self.set_proc_state(
                pid,
                ProcState.MEDIUM,
                preserve_high=True,
                register_medium=True,
            )

            if not changed:
                return ProcState.HIGH

            state = ProcState.MEDIUM

        # 신뢰도 확인 중 HIGH가 되었거나
        # SUSPICIOUS의 실효 상태가 MEDIUM인 경우를 처리
        async with self._pid_lock:
            current = self._proc_state.get(pid, ProcState.LOW)

            if current == ProcState.HIGH:
                return ProcState.HIGH

            if state == ProcState.MEDIUM and pid not in self._medium_pids:
                self._medium_pids[pid] = trio.current_time()

        return state

    def _find_open_fd_for_path(self, path: str) -> Optional[int]:
        """열린 fd 검색 helper"""

        for fh, (_pid, fh_path, _flags) in self._fh_info.items():
            if fh_path != path:
                continue

            fd = self._fd_map.get(fh)

            if fd is not None:
                return fd

        return None

    def _is_honeypot_path(self, path: str) -> bool:
        """경로가 실제 GardFS honeypot 디렉터리 내부인지 확인"""

        honeypot_dir = os.path.realpath(get_honeypot_dir(self.root))
        target = os.path.realpath(path)

        try:
            return os.path.commonpath([target, honeypot_dir]) == honeypot_dir
        except ValueError:
            # 서로 다른 드라이브 등으로 commonpath 계산이 불가능한 경우
            return False

    def _emit_honeypot_event(
        self,
        pid: int,
        op: str,
        path: str,
        size: int = 0,
        off: int = -1,
        flags: int = 0,
        new_path: Optional[str] = None,
        applied: bool = False,
    ) -> None:
        self._emit(
            FsEvent(
                ts_ns=time.time_ns(),
                pid=pid,
                op=op,
                path=path,
                size=size,
                off=off,
                flags=flags,
                new_path=new_path,
                applied=applied,
            )
        )

        print(f"[HONEYPOT] pid={pid} op={op} blocked path={path}")

    # ---------------------------------- FUSE ops ---------------------------------- #
    async def access(self, inode, mode, ctx=None):
        # pyfuse3는 반환값이 참일 때만 허용한다. None이면 chdir/access(2)가 EACCES로 실패한다.
        return True

    async def statfs(self, ctx=None):
        # 파일시스템 통계(블록 크기 등)를 underlay에서 그대로 전달한다.
        # 미구현 시 pyfuse3가 ENOSYS를 던져 df나 statfs(2)/statvfs(3)를 쓰는
        # 프로그램(일부 랜섬웨어의 블록 크기 조회 포함)이 실패한다.
        try:
            s = os.statvfs(self.root)
        except OSError as e:
            raise pyfuse3.FUSEError(e.errno)

        out = pyfuse3.StatvfsData()
        out.f_bsize = s.f_bsize
        out.f_frsize = s.f_frsize
        out.f_blocks = s.f_blocks
        out.f_bfree = s.f_bfree
        out.f_bavail = s.f_bavail
        out.f_files = s.f_files
        out.f_ffree = s.f_ffree
        out.f_favail = s.f_favail
        out.f_namemax = s.f_namemax
        return out

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

        state = await self._resolve_effective_state(pid)

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
            self._emit(
                FsEvent(ts_ns=time.time_ns(), pid=pid, op="create", path=p, flags=flags)
            )

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

            label = (
                "스테이징 (underlay 미생성)"
                if state == ProcState.MEDIUM
                else "HIGH 차단 (underlay 미생성)"
            )
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
        self._emit(
            FsEvent(ts_ns=time.time_ns(), pid=pid, op="create", path=p, flags=flags)
        )

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
                state = self._resolve_suspicious_state(pid)

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

        # 허니팟 디렉터리는 실제 삭제 전에 이벤트를 기록 및 차단
        if self._collect is None and self._is_honeypot_path(p):
            self._emit_honeypot_event(
                pid=pid,
                op="rmdir",
                path=p,
            )

            raise pyfuse3.FUSEError(errno.EACCES)

        override = self._get_forced_state(pid)

        if override is not None:
            await self.set_proc_state(pid, override)
            state = override
        else:
            state = await self.get_proc_state(pid)

            if state == ProcState.SUSPICIOUS:
                state = self._resolve_suspicious_state(pid)

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
                entries.append(
                    (e.name.encode("utf-8", "surrogateescape"), self._stat_to_attr(st))
                )

        for i, (name_b, attr) in enumerate(entries[int(off) :], start=int(off)):
            if not pyfuse3.readdir_reply(token, name_b, attr, i + 1):
                break

    async def releasedir(self, fh):
        # opendir에서 발급한 fh 정리
        self._dir_fh_path.pop(fh, None)

    async def open(self, inode, flags, ctx=None):
        path = self._inode_path.get(inode)

        if path is None:
            raise pyfuse3.FUSEError(errno.ENOENT)

        # os.open() 전에 요청 PID 확인
        pid = ctx.pid if ctx is not None else -1

        # os.open() 전에 honeypot 접근 차단
        if self._collect is None and self._is_honeypot_path(path):
            self._emit_honeypot_event(
                pid=pid,
                op="open",
                path=path,
                flags=flags,
            )
            raise pyfuse3.FUSEError(errno.EACCES)

        state = await self._resolve_effective_state(pid)

        # O_TRUNC는 os.open() 순간 원본 파일을 비우므로 사전 차단
        if state == ProcState.HIGH and flags & os.O_TRUNC:
            from guardfs.stage2.policy.high import (
                handle_open_trunc_high,
            )

            await handle_open_trunc_high(
                path=path,
                flags=flags,
                pid=pid,
                ops=self,
            )

            raise pyfuse3.FUSEError(errno.EACCES)

        # MEDIUM(SUSPICIOUS 매핑 포함)에서도 O_TRUNC는 os.open() 순간
        # 원본을 비워버리므로, write 버퍼링과 동일하게 스테이징으로 유도한다.
        # (기존에는 여기서 바로 os.open(p, flags)가 실행되어 write()의
        # 버퍼링 로직이 개입하기도 전에 원본이 이미 잘려나갔다.)
        if state == ProcState.MEDIUM and flags & os.O_TRUNC:
            staging_path = os.path.join(self._staging_dir, f"fh_{self._next_fh}")

            try:
                fd = os.open(staging_path, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600)
            except OSError as e:
                raise pyfuse3.FUSEError(e.errno)

            fh = self._next_fh
            self._next_fh += 1
            self._fd_map[fh] = fd
            self._fh_info[fh] = (pid, path, flags)
            self._staging_fh[fh] = staging_path
            self._staging_pid[pid].append(staging_path)
            self._trunc_paths[pid].add(path)

            self._emit(
                FsEvent(
                    ts_ns=time.time_ns(), pid=pid, op="open", path=path, flags=flags
                )
            )

            print(
                f"[OPEN] pid={pid} path={path} O_TRUNC 요청 → 스테이징 유도 (원본 보존)"
            )

            fi = pyfuse3.FileInfo()
            fi.fh = fh
            fi.direct_io = False

            return fi

        try:
            fd = os.open(path, flags)
        except OSError as e:
            raise pyfuse3.FUSEError(e.errno)

        fh = self._next_fh
        self._next_fh += 1

        self._fd_map[fh] = fd
        self._fh_info[fh] = (pid, path, flags)

        self._emit(
            FsEvent(
                ts_ns=time.time_ns(),
                pid=pid,
                op="open",
                path=path,
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

        # 테스트용 강제 상태가 있으면 우선 적용
        override = self._get_forced_state(pid)

        if override is not None:
            state = override
        else:
            state = await self.get_proc_state(pid)

        # HIGH 상태에서는 실제 파일 내용을 읽지 않기
        if state == ProcState.HIGH:
            print(f"[HIGH] pid={pid} read blocked path={path}\n")

            raise pyfuse3.FUSEError(errno.EACCES)

        # 실제 os.read() 전에 honeypot 경로를 확인
        if self._collect is None and self._is_honeypot_path(path):
            self._emit_honeypot_event(
                pid=pid,
                op="read",
                path=path,
                size=size,
                off=off,
            )
            raise pyfuse3.FUSEError(errno.EACCES)

        self._emit(
            FsEvent(
                ts_ns=time.time_ns(),
                pid=pid,
                op="read",
                path=path,
                size=size,
                off=off,
            )
        )

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

        # create로 발급된 핸들을 통한 허니팟 write도 실제 기록 전에 차단
        if self._collect is None and self._is_honeypot_path(path):
            self._emit_honeypot_event(
                pid=pid,
                op="write",
                path=path,
                size=len(buf),
                off=off,
            )

            raise pyfuse3.FUSEError(errno.EACCES)

        sample_data = None
        original_data = None
        sample_size = 0

        if off >= 0 and buf:
            sample_size = min(
                len(buf),
                ENTROPY_MAX_EVENT_SAMPLE_SIZE,
            )

            sample_data = bytes(buf[:sample_size])

            # write 이전 원본 샘플: Entropy Delta 계산용
            try:
                original_data = os.pread(fd, sample_size, off)
            except OSError:
                original_data = None

        self._emit(
            FsEvent(
                ts_ns=time.time_ns(),
                pid=pid,
                op="write",
                path=path,
                size=len(buf),
                off=off,
                entropy=None,
                sample_data=sample_data,
                original_data=original_data,
            )
        )

        state = await self._resolve_effective_state(pid)

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
                await handle_setattr_high(
                    p, f"CHMOD(mode={stat_mod.S_IMODE(attr.st_mode):o})", pid, self
                )
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
            self._emit(
                FsEvent(
                    ts_ns=time.time_ns(),
                    pid=pid,
                    op="chmod",
                    path=p,
                    flags=stat_mod.S_IMODE(attr.st_mode),
                )
            )
        if fields.update_uid or fields.update_gid:
            self._emit(FsEvent(ts_ns=time.time_ns(), pid=pid, op="chown", path=p))
        if fields.update_atime or fields.update_mtime:
            self._emit(FsEvent(ts_ns=time.time_ns(), pid=pid, op="utime", path=p))

    async def truncate(self, inode, size, ctx=None):
        p = self._inode_path.get(inode)

        if p is None:
            raise pyfuse3.FUSEError(errno.ENOENT)

        pid = ctx.pid if ctx is not None else -1

        # 실제 파일 크기를 변경하기 전에 허니팟 경로를 차단
        if self._collect is None and self._is_honeypot_path(p):
            self._emit_honeypot_event(
                pid=pid,
                op="truncate",
                path=p,
                size=size,
            )

            raise pyfuse3.FUSEError(errno.EACCES)

        if await self.get_proc_state(pid) == ProcState.HIGH:
            from guardfs.stage2.policy.high import handle_truncate_high

            await handle_truncate_high(p, size, pid, self)

            return

        try:
            with open(p, "r+b") as f:
                f.truncate(size)
        except OSError as e:
            raise pyfuse3.FUSEError(e.errno)

        self._emit(
            FsEvent(ts_ns=time.time_ns(), pid=pid, op="truncate", path=p, size=size)
        )

    async def ftruncate(self, fh, size):
        fd = self._fd_map.get(fh)

        if fd is None:
            raise pyfuse3.FUSEError(errno.EBADF)

        pid, path, _flags = self._fh_info.get(fh, (-1, "?", 0))

        # 열린 핸들을 통한 크기 변경도 실제 변경 전에 허니팟 경로를 차단
        if self._collect is None and self._is_honeypot_path(path):
            self._emit_honeypot_event(
                pid=pid,
                op="ftruncate",
                path=path,
                size=size,
            )

            raise pyfuse3.FUSEError(errno.EACCES)

        if await self.get_proc_state(pid) == ProcState.HIGH:
            from guardfs.stage2.policy.high import handle_truncate_high

            await handle_truncate_high(path, size, pid, self)

            return

        try:
            os.ftruncate(fd, size)
        except OSError as e:
            raise pyfuse3.FUSEError(e.errno)

        self._emit(
            FsEvent(ts_ns=time.time_ns(), pid=pid, op="ftruncate", path=path, size=size)
        )

    async def unlink(self, parent_inode, name, ctx=None):
        path = self._resolve_path(parent_inode, name)
        pid = ctx.pid if ctx is not None else -1

        # 허니팟은 실제 삭제나 staging 처리 전에 차단
        if self._collect is None and self._is_honeypot_path(path):
            self._emit_honeypot_event(
                pid=pid,
                op="unlink",
                path=path,
            )
            raise pyfuse3.FUSEError(errno.EACCES)

        state = await self._resolve_effective_state(pid)

        if state == ProcState.HIGH:
            from guardfs.stage2.policy.high import handle_unlink_high

            await handle_unlink_high(path, pid, self)
            return

        if state == ProcState.MEDIUM:
            from guardfs.stage2.policy.medium import handle_unlink_medium

            await handle_unlink_medium(path, pid, self)
            self._emit(
                FsEvent(
                    ts_ns=time.time_ns(),
                    pid=pid,
                    op="unlink",
                    path=path,
                )
            )
            return

        try:
            os.unlink(path)
        except OSError as e:
            raise pyfuse3.FUSEError(e.errno)

        self._emit(FsEvent(ts_ns=time.time_ns(), pid=pid, op="unlink", path=path))

    async def rename(
        self, parent_inode_old, name_old, parent_inode_new, name_new, flags, ctx=None
    ):
        oldp = self._resolve_path(parent_inode_old, name_old)
        newp = self._resolve_path(parent_inode_new, name_new)

        pid = ctx.pid if ctx is not None else -1

        # 출발지 또는 목적지가 허니팟이면 실제 rename 전에 차단
        if self._collect is None and (
            self._is_honeypot_path(oldp) or self._is_honeypot_path(newp)
        ):
            self._emit(
                FsEvent(
                    ts_ns=time.time_ns(),
                    pid=pid,
                    op="rename",
                    path=oldp,
                    new_path=newp,
                    applied=False,
                )
            )

            print(f"[HONEYPOT] pid={pid} op=rename blocked path={oldp} new_path={newp}")

            raise pyfuse3.FUSEError(errno.EACCES)

        if await self.get_proc_state(pid) == ProcState.HIGH:
            from guardfs.stage2.policy.high import handle_rename_high

            await handle_rename_high(oldp, newp, pid, self)
            return

        ev = FsEvent(
            ts_ns=time.time_ns(),
            pid=pid,
            op="rename",
            path=oldp,
            new_path=newp,
        )

        if self._collect is None:
            blocked, reason = self._stage1.precheck(ev)
        else:
            blocked, reason = False, None

        if blocked:
            ev.applied = False
            self._emit(ev)

            print(
                f"[PRECHECK] pid={pid} op=rename "
                f"path={oldp} new_path={newp} "
                f"reason={reason} blocked"
            )

            raise pyfuse3.FUSEError(errno.EACCES)

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
            self._inode_path[inode] = newp + path[len(oldp) :]

        for fh, (fh_pid, path, fh_flags) in list(self._fh_info.items()):
            if path == oldp or path.startswith(old_prefix):
                self._fh_info[fh] = (
                    fh_pid,
                    newp + path[len(oldp) :],
                    fh_flags,
                )

        for fh, path in list(self._dir_fh_path.items()):
            if path == oldp or path.startswith(old_prefix):
                self._dir_fh_path[fh] = newp + path[len(oldp) :]

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
        file_size = 0

        if fd is not None:
            try:
                stat_result = os.fstat(fd)
                inode = stat_result.st_ino
                file_size = stat_result.st_size
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
                size=file_size,
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
    """
    동적 모델 v5(rf_model_v5.pkl)의 입력 피처를 PID 단위로 온라인 집계한다.

    v5는 런타임이 실제로 보는 신호(FUSE 이벤트, PID 단위)에 맞춘 모델이다.
    여기서 만드는 피처는 수집 로그에서 오프라인으로 뽑는
    models/dynamic/collect/features.py:compute_features 와 "정확히 동일한"
    값이어야 한다(그래야 학습 분포와 추론 분포가 일치). 아래 로직은
    compute_features 를 증분(incremental) 방식으로 그대로 옮긴 것이다.

    다른 점(의도적 제외):
      - proc_count : PID 단위라 항상 1 → 피처에서 제외
      - crypto_calls: FUSE엔 CRYPTO op이 없음 → 피처에서 제외
    이 둘을 뺀 22개가 v5 스키마(models/dynamic/feature_cols_v5.json)이다.
    """

    HIGH_ENTROPY = ENTROPY_THRESHOLD  # 7.0, features.py HIGH_ENTROPY와 동일
    MUTATING_OPS = {"WRITE", "CREATE", "RENAME", "UNLINK", "TRUNCATE", "CHMOD"}
    _OP_NAMES = {"ftruncate": "TRUNCATE"}  # fuse_logger와 동일한 op 정규화

    @staticmethod
    def _ext(path) -> str:
        return os.path.splitext(path)[1].lower() if path else ""

    def __init__(self):
        # --- Stage1 1초 윈도우 게이트 전용 (reset마다 초기화) ---
        self.w_win = 0  # 윈도우 내 WRITE 수
        self.d_win = 0  # 윈도우 내 삭제(UNLINK+RMDIR) 수
        self.e_sum = 0  # 윈도우 내 고엔트로피 write 수

        # --- 프로세스 생애 누적 (v5 피처용; reset에서 유지) ---
        self._op_counts = {}
        self._total = 0
        self._first_ts = None
        self._last_ts = None
        self._read_paths = set()
        self._read_then_overwrite = 0
        self._write_events = 0
        self._total_renames = 0
        self._ext_change_renames = 0
        self._new_exts = set()
        self._touched_files = set()
        self._touched_dirs = set()
        self._write_bytes = 0
        self._write_size_samples = 0
        self._he_write = 0
        self._entropy_writes = 0
        self._entropy_sum = 0.0
        self._entropy_available = False

    def reset(self) -> None:
        """1초 윈도우 종료 시 호출. 게이트용 윈도우 카운터만 초기화한다."""
        self.w_win = 0
        self.d_win = 0
        self.e_sum = 0

    def mean_entropy(self) -> float:
        # stats_collector의 stat_anomaly 게이트에서 사용.
        # 윈도우 내 고엔트로피 write 카운트를 반환한다.
        return float(self.e_sum)

    def _norm_op(self, op: str) -> str:
        return self._OP_NAMES.get(op, op.upper())

    def update(self, ev) -> None:
        op = self._norm_op(ev.op)

        self._total += 1
        self._op_counts[op] = self._op_counts.get(op, 0) + 1
        if self._first_ts is None:
            self._first_ts = ev.ts_ns
        self._last_ts = ev.ts_ns

        path = ev.path
        if op in self.MUTATING_OPS and path:
            self._touched_files.add(path)
            self._touched_dirs.add(os.path.dirname(path))

        if op == "READ" and path:
            self._read_paths.add(path)

        elif op == "WRITE":
            self._write_events += 1
            self.w_win += 1
            if path and path in self._read_paths:
                self._read_then_overwrite += 1

            size = ev.size
            if isinstance(size, (int, float)) and size >= 0:
                self._write_bytes += size
                self._write_size_samples += 1

            ent = ev.entropy
            if ent is not None:
                self._entropy_available = True
                self._entropy_writes += 1
                self._entropy_sum += ent
                if ent >= self.HIGH_ENTROPY:
                    self._he_write += 1
                    self.e_sum += 1

        elif op == "RENAME":
            self._total_renames += 1
            if ev.new_path and self._ext(path) != self._ext(ev.new_path):
                self._ext_change_renames += 1
                self._new_exts.add(self._ext(ev.new_path))

        elif op in ("UNLINK", "RMDIR"):
            self.d_win += 1

    def to_feature_row(self) -> dict:
        """
        ML 입력 행(22피처). features.py:compute_features 와 동일한 산식·반올림.
        (게이트가 참조하는 w_win/d_win/e_sum 과 혼동하지 말 것)
        """
        if self._first_ts is not None:
            duration = max((self._last_ts - self._first_ts) / 1e9, 0.0)
        else:
            duration = 0.0
        total = self._total
        denom = max(duration, 1.0)  # 매우 짧은 실행에서 속도가 튀지 않게

        n_write = self._op_counts.get("WRITE", 0)
        n_unlink = self._op_counts.get("UNLINK", 0)
        n_rename = self._op_counts.get("RENAME", 0)
        n_create = self._op_counts.get("CREATE", 0)
        n_read = self._op_counts.get("READ", 0)

        def d(a, b):
            return a / b if b else 0.0

        return {
            "duration_sec": round(duration, 4),
            "total_events": total,
            "write_per_sec": round(d(n_write, denom), 4),
            "unlink_per_sec": round(d(n_unlink, denom), 4),
            "rename_per_sec": round(d(n_rename, denom), 4),
            "create_per_sec": round(d(n_create, denom), 4),
            "write_ratio": round(d(n_write, total), 4),
            "unlink_ratio": round(d(n_unlink, total), 4),
            "rename_ratio": round(d(n_rename, total), 4),
            "read_ratio": round(d(n_read, total), 4),
            "high_entropy_write_count": self._he_write,
            "high_entropy_write_ratio": round(
                d(self._he_write, self._entropy_writes), 4
            ),
            "mean_write_entropy": round(d(self._entropy_sum, self._entropy_writes), 4),
            "entropy_available": int(self._entropy_available),
            "read_then_overwrite_ratio": round(
                d(self._read_then_overwrite, self._write_events), 4
            ),
            "ext_change_rename_ratio": round(
                d(self._ext_change_renames, self._total_renames), 4
            ),
            "distinct_ext_after_rename": len(self._new_exts),
            "unique_files_touched": len(self._touched_files),
            "unique_dirs_touched": len(self._touched_dirs),
            "files_per_dir": round(
                d(len(self._touched_files), len(self._touched_dirs)), 4
            ),
            "total_write_bytes": self._write_bytes,
            "mean_write_bytes": round(
                d(self._write_bytes, self._write_size_samples), 2
            ),
        }


async def main(
    mountpoint: str,
    root: str,
    collect_logger: Optional[FuseCollectLogger] = None,
):
    honeypot_dir = get_honeypot_dir(root)

    stage1 = Stage1Detector(honeypot_dir)
    ops = Passthrough(root, stage1, collect_logger)

    pyfuse3.init(ops, mountpoint, set())

    try:
        async with trio.open_nursery() as nursery:
            if collect_logger is None:
                nursery.start_soon(
                    stats_collector,
                    ops._recv_chan,
                    ops._log_path,
                    stage1,
                    ops,
                )

                nursery.start_soon(
                    stage2_worker,
                    ops._stage2_recv,
                    ops,
                )

            await pyfuse3.main()

    finally:
        pyfuse3.close(unmount=True)


def _run_id_arg(value: str) -> str:
    if not RUN_ID_PATTERN.match(value):
        raise argparse.ArgumentTypeError(
            "영문, 숫자, '.', '_', '-'만 사용할 수 있습니다"
        )
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
