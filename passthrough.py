#!/usr/bin/env python3
import os
import sys
import errno
import time
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

def _full_path(root: str, path: str) -> str:
    if path.startswith("/"):
        path = path[1:]
    return os.path.join(root, path)

def get_exe_path(pid: int) -> Optional[str]:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except Exception:
        return None

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
    new_path: Optional[str] = None
    exe_path: Optional[str] = None

class ProcState(str, Enum):
    LOW = "LOW"
    SUSPICIOUS = "SUSPICIOUS"

class PidStats:
    def __init__(self):
        self.write_count = 0
        self.read_count = 0
        self.rename_count = 0
        self.unlink_count = 0
        self.open_count = 0

        self.total_write_bytes = 0
        self.entropy_sum = 0.0
        self.max_entropy = 0.0

        self.files = set()

    def reset(self) -> None:
        self.__init__()

    def mean_entropy(self) -> float:
        return self.entropy_sum / self.write_count if self.write_count else 0.0

    def update(self, ev) -> None:
        self.files.add(ev.path)

        if ev.op == "write":
            self.write_count += 1
            self.total_write_bytes += ev.size
            if ev.entropy is not None:
                self.entropy_sum += ev.entropy
                self.max_entropy = max(self.max_entropy, ev.entropy)

        elif ev.op == "read":
            self.read_count += 1

        elif ev.op == "open":
            self.open_count += 1

        elif ev.op == "rename":
            self.rename_count += 1

        elif ev.op == "unlink":
            self.unlink_count += 1

    def to_feature_row(self) -> dict:
        return {
            "write_count": self.write_count,
            "read_count": self.read_count,
            "open_count": self.open_count,
            "rename_count": self.rename_count,
            "unlink_count": self.unlink_count,
            "total_write_bytes": self.total_write_bytes,
            "avg_entropy": self.mean_entropy(),
            "max_entropy": self.max_entropy,
            "unique_file_count": len(self.files),
        }


async def stats_collector(
    recv_chan: trio.MemoryReceiveChannel,
    log_path: str,
    honeypot_dir: str,
    ops: "Passthrough",
) -> None:
    """
    - EventLogger   : 모든 이벤트를 JSONL로 저장
    - PidStats      : PID별 최근 행동을 malware_dataset.csv feature 구조로 집계
    - Stage1Detector: 경량 탐지 수행
    """
    WINDOW_S = 1.0
    C_TH = 10
    D_TH = 10

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
                        feature_row = st.to_feature_row()

                        suspicious = (
                            feature_row["E_sum"] >= 1
                            or feature_row["D_sum"] >= D_TH
                            or feature_row["C_sum"] >= C_TH
                        )

                        if suspicious and pid > 0:
                            print(
                                f"[SUSPICIOUS] pid={pid} "
                                f"O_sum={feature_row['O_sum']} "
                                f"C_sum={feature_row['C_sum']} "
                                f"D_sum={feature_row['D_sum']} "
                                f"E_sum={feature_row['E_sum']}"
                            )

                            await ops.mark_suspect(
                                pid,
                                reason="stat_anomaly",
                                path="",
                                features=feature_row,
                                exe_path=st.exe_path
                            )

                        st.reset()

                    next_tick += WINDOW_S
                    continue

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
                        features=feature_row,
                        exe_path=ev.exe_path
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
        if ev.exe_path is None and ev.pid > 0:
            ev.exe_path = get_exe_path(ev.pid)

        try:
            self._send_chan.send_nowait(ev)
        except trio.WouldBlock:
            pass

    async def mark_suspect(self, pid: int, reason: str = "", path: str = "", features=None, exe_path: Optional[str] = None) -> None:
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
            "features": features,
            "exe_path": exe_path,
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
        oldp = self._resolve_path(parent_inode_old, name_old)
        newp = self._resolve_path(parent_inode_new, name_new)

        pid = ctx.pid if ctx is not None else -1
        exe_path = get_exe_path(pid)   # 이 줄 추가

        try:
            os.rename(oldp, newp)
        except OSError as e:
            raise pyfuse3.FUSEError(e.errno)

        self._emit(
            FsEvent(
                ts_ns=time.time_ns(),
                pid=pid,
                op="rename",
                path=oldp,
                new_path=newp,
                exe_path=exe_path
            )
        )

    async def release(self, fh):
        pid, path, flags = self._fh_info.pop(fh, (-1, "?", 0))
        self._emit(FsEvent(ts_ns=time.time_ns(), pid=pid, op="release", path=path, flags=flags))

        fd = self._fd_map.pop(fh, None)
        if fd is not None:
            os.close(fd)

def extract_static_features(exe_path: str) -> dict:
    import os
    from collections import Counter

    try:
        with open(exe_path, "rb") as f:
            data = f.read()
    except Exception:
        return None

    if not data.startswith(b"\x7fELF"):
        return None

    # label 제외한 모든 정적 모델 컬럼을 0으로 초기화
    features = {col: 0 for col in STATIC_COLS}

    if "file_size" in features:
        features["file_size"] = os.path.getsize(exe_path)

    if "is_64bit" in features:
        features["is_64bit"] = 1.0 if len(data) > 4 and data[4] == 2 else 0.0

    byte_counts = Counter(data)

    for col in STATIC_COLS:
        if col.startswith("byte_f_"):
            try:
                idx = int(col.replace("byte_f_", ""))
                features[col] = byte_counts.get(idx % 256, 0)
            except Exception:
                features[col] = 0

        elif col.startswith("opcode_f_"):
            features[col] = 0

    if "elf_type_ET_DYN" in features:
        features["elf_type_ET_DYN"] = 1 if b".interp" in data else 0

    if "elf_type_ET_EXEC" in features:
        features["elf_type_ET_EXEC"] = 0 if features.get("elf_type_ET_DYN", 0) else 1

    return features

async def stage2_worker(recv_chan, ops: "Passthrough"):
    import os
    import pandas as pd
    import joblib

    # -----------------------
    # 모델 로드
    # -----------------------
    dynamic_model = joblib.load("detect_dynamic/dataset/csv_files/best_model.pkl")
    dynamic_scaler = joblib.load("detect_dynamic/dataset/csv_files/scaler.pkl")

    static_model = joblib.load("final_rf_model.pkl")

    # -----------------------
    # 정적 CSV 컬럼 로드
    # -----------------------
    global STATIC_COLS

    STATIC_COLS = pd.read_csv(
        "fused_model/merged_topk_balanced_k200.csv",
        nrows=0
    ).columns.tolist()

    STATIC_COLS = [c for c in STATIC_COLS if c.strip().lower() != "label"]

    # -----------------------
    # 메인 루프
    # -----------------------
    async with recv_chan:
        async for item in recv_chan:
            pid = item["pid"]
            reason = item["reason"]
            path = item["path"]
            features = item["features"]
            exe_path = item.get("exe_path")

            print(
                f"[STAGE1.5] pid={pid} reason={reason} "
                f"path={path} exe={exe_path}"
            )

            # -----------------------
            # 1. Dynamic ML
            # -----------------------
            X_dynamic = pd.DataFrame([features])
            X_dynamic_scaled = dynamic_scaler.transform(X_dynamic.values)

            dynamic_pred = dynamic_model.predict(X_dynamic_scaled)[0]
            dynamic_prob = dynamic_model.predict_proba(X_dynamic_scaled)[0][1]

            # -----------------------
            # 2. Static ML
            # -----------------------
            static_pred = None
            static_prob = None

            if exe_path and os.path.exists(exe_path):
                try:
                    static_features = extract_static_features(exe_path)

                    if static_features is not None:
                        X_static = pd.DataFrame([static_features])

                        # 🔥 컬럼 맞추기 (핵심)
                        # 🔥 컬럼 맞추기
                        X_static = X_static.reindex(columns=STATIC_COLS, fill_value=0)

                        static_pred = static_model.predict(X_static)[0]
                        static_prob = static_model.predict_proba(X_static)[0][1]

                except Exception as e:
                    print(f"[STATIC ERROR] exe={exe_path} error={e}")

            # -----------------------
            # 3. Fusion (1/2)
            # -----------------------
            if static_prob is not None:
                final_score = 0.5 * dynamic_prob + 0.5 * static_prob
            else:
                final_score = dynamic_prob

            final_pred = 1 if final_score >= 0.5 else 0

            # -----------------------
            # 출력
            # -----------------------
            print(
                f"[RESULT] pid={pid} "
                f"dynamic_pred={dynamic_pred} dynamic_prob={dynamic_prob:.4f} "
                f"static_pred={static_pred} static_prob={static_prob if static_prob is not None else 'N/A'} "
                f"final_score={final_score:.4f} final_pred={final_pred}"
            )

            # -----------------------
            # 큐 정리
            # -----------------------
            async with ops._pid_lock:
                ops._queued_stage2.discard(pid)

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
        self.exe_path: Optional[str] = None
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
        if self.exe_path is None and ev.exe_path:
            self.exe_path = ev.exe_path

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
