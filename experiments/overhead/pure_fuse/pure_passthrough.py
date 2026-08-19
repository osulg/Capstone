#!/usr/bin/env python3
"""Pure pyfuse3 passthrough with measurement-only logging.

No Stage1, Stage2, entropy, honeypot, state machine, staging, or blocking exists.
It records the same latency.csv columns used by the user's analysis pipeline and
samples this daemon's CPU/RSS into resource_usage_pure_fuse.csv.

For an uncontaminated end-to-end FUSE baseline, use the unlogged
pure_fuse_passthrough.py with an external benchmark. This logged variant is for
matching the existing GuardFS result format.
"""
import csv
import errno
import os
import stat
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Tuple, List

import psutil
import pyfuse3
import trio

LOG_DIR = Path(os.path.expanduser("~/pure_fuse_lab/logs"))
LATENCY_CSV = LOG_DIR / "latency.csv"
RESOURCE_CSV = LOG_DIR / "resource_usage_pure_fuse.csv"

LOG_START_FILE = LOG_DIR / ".start_logging"
LOG_STOP_FILE = LOG_DIR / ".stop_logging"
WORKLOAD_STATE_FILE = LOG_DIR / ".workload_state"

CURRENT_WORKLOAD_STATE = ""
LOGGING_ENABLED = False

_LOGGING_LOCK = threading.Lock()


def refresh_logging_state() -> bool:
    """
    두 번째 터미널의 제어 파일로 측정을 시작하거나 중지한다.

    시작:
        touch ~/pure_fuse_lab/logs/.start_logging

    중지:
        touch ~/pure_fuse_lab/logs/.stop_logging
    """
    global LOGGING_ENABLED

    with _LOGGING_LOCK:
        if LOG_STOP_FILE.exists():
            LOGGING_ENABLED = False
            try:
                LOG_STOP_FILE.unlink()
            except OSError:
                pass
            print("[MEASURE] logging stopped")
            return False

        if LOG_START_FILE.exists() and not LOGGING_ENABLED:
            # 마운트 직후 자동 조회 로그와 기존 로그 제거
            for path in (LATENCY_CSV, RESOURCE_CSV):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
                except OSError as error:
                    print(f"[MEASURE WARNING] cannot reset {path}: {error}")

            LOGGING_ENABLED = True

            try:
                LOG_START_FILE.unlink()
            except OSError:
                pass

            print("[MEASURE] logging started; warm-up logs cleared")

        return LOGGING_ENABLED
    
    
def refresh_workload_state() -> None:
    """
    normal_workload.sh가 기록한 현재 workload 단계를 읽고,
    단계가 변경되었을 때 터미널에 배너를 한 번 출력한다.
    """
    global CURRENT_WORKLOAD_STATE

    try:
        if not WORKLOAD_STATE_FILE.exists():
            return

        new_state = (
            WORKLOAD_STATE_FILE
            .read_text(encoding="utf-8")
            .strip()
        )

    except OSError:
        return

    if not new_state:
        return

    if new_state == CURRENT_WORKLOAD_STATE:
        return

    CURRENT_WORKLOAD_STATE = new_state

    print()
    print("=" * 72)
    print(f"[CURRENT WORKLOAD] {new_state}")
    print("=" * 72)
    print()


def append_csv(path: Path, fieldnames: List[str], row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    need_header = not path.exists() or path.stat().st_size == 0
    with path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if need_header:
            writer.writeheader()
        writer.writerow(row)


class ActivityTracker:
    def __init__(self):
        self._lock = threading.Lock()
        self.operation = "idle"
        self.pid = -1
        self.path = ""
        self.active = 0

    def begin(self, operation: str, pid: int, path: str):
        with self._lock:
            self.active += 1
            self.operation = operation
            self.pid = pid
            self.path = path

    def end(self):
        with self._lock:
            self.active = max(0, self.active - 1)
            if self.active == 0:
                self.operation = "idle"
                self.pid = -1
                self.path = ""

    def snapshot(self):
        with self._lock:
            return self.operation, self.pid, self.path


ACTIVITY = ActivityTracker()


def log_latency(op: str, pid: int, path: str, start_ns: int, detail: str):
    if not refresh_logging_state():
        return
    
    refresh_workload_state()

    end_ns = time.perf_counter_ns()
    elapsed_ms = (end_ns - start_ns) / 1_000_000
    append_csv(
        LATENCY_CSV,
        ["event_type", "pid", "op", "path", "start_ns", "end_ns", "elapsed_ms", "detail"],
        {
            "event_type": "basic_io",
            "pid": pid,
            "op": op,
            "path": path,
            "start_ns": start_ns,
            "end_ns": end_ns,
            "elapsed_ms": round(elapsed_ms, 6),
            "detail": detail,
        },
    )
    print(f"[LATENCY] basic_io PID={pid:<6} OP={op:<10} {elapsed_ms:8.3f} ms {detail}")


@contextmanager
def measured(op: str, pid: int, path: str):
    start_ns = time.perf_counter_ns()
    ACTIVITY.begin(op, pid, path)
    result = {"detail": "result=failed"}
    try:
        yield result
    finally:
        log_latency(op, pid, path, start_ns, result["detail"])
        ACTIVITY.end()


def resource_monitor(pid: int, interval_s: float = 0.02):
    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return

    columns = [
        "timestamp_ns", "elapsed_s", "cpu_percent", "memory_rss_mb",
        "memory_percent", "operation", "operation_pid", "operation_path",
    ]
    started = time.perf_counter_ns()
    proc.cpu_percent(interval=None)

    while True:
        try:
            if not proc.is_running() or proc.status() == psutil.STATUS_ZOMBIE:
                break
            if not refresh_logging_state():
                time.sleep(interval_s)
                continue

            operation, operation_pid, operation_path = ACTIVITY.snapshot()
            info = proc.memory_info()
            append_csv(
                RESOURCE_CSV,
                columns,
                {
                    "timestamp_ns": time.time_ns(),
                    "elapsed_s": round((time.perf_counter_ns() - started) / 1e9, 6),
                    "cpu_percent": round(proc.cpu_percent(interval=None), 2),
                    "memory_rss_mb": round(info.rss / (1024 * 1024), 2),
                    "memory_percent": round(proc.memory_percent(), 4),
                    "operation": operation,
                    "operation_pid": operation_pid,
                    "operation_path": operation_path,
                },
            )
            time.sleep(interval_s)
        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
            break


class PurePassthrough(pyfuse3.Operations):
    def __init__(self, root: str):
        super().__init__()
        self.root = os.path.realpath(root)
        self._inode_path: Dict[int, str] = {pyfuse3.ROOT_INODE: self.root}
        self._fd_map: Dict[int, int] = {}
        self._fh_info: Dict[int, Tuple[int, str, int]] = {}
        self._dir_fh_path: Dict[int, str] = {}
        self._next_fh = 1

    def _new_fh(self):
        fh = self._next_fh
        self._next_fh += 1
        return fh

    def _path(self, inode):
        path = self._inode_path.get(inode)
        if path is None:
            raise pyfuse3.FUSEError(errno.ENOENT)
        return path

    def _resolve(self, parent_inode, name):
        return os.path.join(self._path(parent_inode), name.decode("utf-8", "surrogateescape"))

    def _register(self, path):
        try:
            st = os.lstat(path)
        except OSError as e:
            raise pyfuse3.FUSEError(e.errno)
        self._inode_path[st.st_ino] = path
        return st

    @staticmethod
    def _attr(st):
        a = pyfuse3.EntryAttributes()
        for name in ["st_ino", "st_mode", "st_nlink", "st_uid", "st_gid", "st_rdev", "st_size", "st_blksize", "st_blocks", "st_atime_ns", "st_mtime_ns", "st_ctime_ns"]:
            setattr(a, name, getattr(st, name))
        a.entry_timeout = 0.0
        a.attr_timeout = 0.0
        return a

    async def getattr(self, inode, ctx=None):
        p = self._path(inode); pid = ctx.pid if ctx else -1
        with measured("getattr", pid, p) as m:
            try: result = self._attr(os.lstat(p))
            except OSError as e: raise pyfuse3.FUSEError(e.errno)
            m["detail"] = "result=success"
            return result

    async def lookup(self, parent_inode, name, ctx=None):
        p = self._resolve(parent_inode, name); pid = ctx.pid if ctx else -1
        with measured("lookup", pid, p) as m:
            result = self._attr(self._register(p)); m["detail"] = "result=success"; return result

    async def create(self, parent_inode, name, mode, flags, ctx=None):
        p = self._resolve(parent_inode, name); pid = ctx.pid if ctx else -1
        with measured("create", pid, p) as m:
            try:
                fd = os.open(p, flags | os.O_CREAT, mode); st = self._register(p)
            except OSError as e: raise pyfuse3.FUSEError(e.errno)
            fh = self._new_fh(); self._fd_map[fh] = fd; self._fh_info[fh] = (pid, p, flags)
            fi = pyfuse3.FileInfo(fh=fh); fi.direct_io = False
            m["detail"] = "result=created"
            return fi, self._attr(st)

    async def open(self, inode, flags, ctx=None):
        p = self._path(inode); pid = ctx.pid if ctx else -1
        with measured("open", pid, p) as m:
            try: fd = os.open(p, flags)
            except OSError as e: raise pyfuse3.FUSEError(e.errno)
            fh = self._new_fh(); self._fd_map[fh] = fd; self._fh_info[fh] = (pid, p, flags)
            fi = pyfuse3.FileInfo(fh=fh); fi.direct_io = False
            m["detail"] = "result=opened"; return fi

    async def read(self, fh, off, size):
        fd = self._fd_map.get(fh)
        if fd is None: raise pyfuse3.FUSEError(errno.EBADF)
        pid, p, _ = self._fh_info.get(fh, (-1, "?", 0))
        with measured("read", pid, p) as m:
            try: result = os.pread(fd, size, off)
            except OSError as e: raise pyfuse3.FUSEError(e.errno)
            m["detail"] = f"result=read, size={len(result)}"; return result

    async def write(self, fh, off, buf):
        fd = self._fd_map.get(fh)
        if fd is None: raise pyfuse3.FUSEError(errno.EBADF)
        pid, p, _ = self._fh_info.get(fh, (-1, "?", 0))
        with measured("write", pid, p) as m:
            try: result = os.pwrite(fd, buf, off)
            except OSError as e: raise pyfuse3.FUSEError(e.errno)
            m["detail"] = f"result=written, size={result}"; return result

    async def unlink(self, parent_inode, name, ctx=None):
        p = self._resolve(parent_inode, name); pid = ctx.pid if ctx else -1
        with measured("unlink", pid, p) as m:
            try: os.unlink(p)
            except OSError as e: raise pyfuse3.FUSEError(e.errno)
            m["detail"] = "result=deleted"

    async def rename(self, old_parent, old_name, new_parent, new_name, flags, ctx=None):
        old = self._resolve(old_parent, old_name); new = self._resolve(new_parent, new_name); pid = ctx.pid if ctx else -1
        with measured("rename", pid, f"{old} -> {new}") as m:
            if flags != 0: raise pyfuse3.FUSEError(errno.EINVAL)
            try: os.rename(old, new)
            except OSError as e: raise pyfuse3.FUSEError(e.errno)
            for ino, cached in list(self._inode_path.items()):
                if cached == old: self._inode_path[ino] = new
                elif cached.startswith(old + os.sep): self._inode_path[ino] = new + cached[len(old):]
            for fh, (fpid, cached, fflags) in list(self._fh_info.items()):
                if cached == old: self._fh_info[fh] = (fpid, new, fflags)
            m["detail"] = "result=renamed"

    async def mkdir(self, parent_inode, name, mode, ctx=None):
        p = self._resolve(parent_inode, name); pid = ctx.pid if ctx else -1
        with measured("mkdir", pid, p) as m:
            try: os.mkdir(p, mode)
            except OSError as e: raise pyfuse3.FUSEError(e.errno)
            result = self._attr(self._register(p)); m["detail"] = "result=created"; return result

    async def rmdir(self, parent_inode, name, ctx=None):
        p = self._resolve(parent_inode, name); pid = ctx.pid if ctx else -1
        with measured("rmdir", pid, p) as m:
            try: os.rmdir(p)
            except OSError as e: raise pyfuse3.FUSEError(e.errno)
            m["detail"] = "result=deleted"

    async def opendir(self, inode, ctx=None):
        p = self._path(inode); pid = ctx.pid if ctx else -1
        with measured("opendir", pid, p) as m:
            fh = self._new_fh(); self._dir_fh_path[fh] = p
            m["detail"] = "result=opened"; return fh

    async def readdir(self, fh, off, token):
        p = self._dir_fh_path.get(fh)
        if p is None: raise pyfuse3.FUSEError(errno.EBADF)
        with measured("readdir", -1, p) as m:
            try: entries = list(os.scandir(p))
            except OSError as e: raise pyfuse3.FUSEError(e.errno)
            added = 0
            for index, entry in enumerate(entries[int(off):], start=int(off)):
                try: st = entry.stat(follow_symlinks=False)
                except FileNotFoundError: continue
                self._inode_path[st.st_ino] = os.path.join(p, entry.name)
                if not pyfuse3.readdir_reply(token, entry.name.encode("utf-8", "surrogateescape"), self._attr(st), index + 1): break
                added += 1
            m["detail"] = f"result=read, size={added}"

    async def releasedir(self, fh):
        self._dir_fh_path.pop(fh, None)

    async def setattr(self, inode, attr, fields, fh, ctx=None):
        p = self._path(inode); pid = ctx.pid if ctx else -1
        op = "truncate" if fields.update_size else "setattr"
        with measured(op, pid, p) as m:
            fd = self._fd_map.get(fh) if fh is not None else None
            try:
                if fields.update_size:
                    os.ftruncate(fd, attr.st_size) if fd is not None else os.truncate(p, attr.st_size)
                if fields.update_mode: os.chmod(p, stat.S_IMODE(attr.st_mode), follow_symlinks=False)
                result = self._attr(os.lstat(p))
            except OSError as e: raise pyfuse3.FUSEError(e.errno)
            m["detail"] = f"result=success, size={attr.st_size if fields.update_size else -1}"; return result

    async def release(self, fh):
        pid, p, _ = self._fh_info.pop(fh, (-1, "?", 0))
        with measured("release", pid, p) as m:
            fd = self._fd_map.pop(fh, None)
            if fd is not None:
                try: os.close(fd)
                except OSError: pass
            m["detail"] = "result=closed"


async def main(mountpoint: str, underlay: str):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    ops = PurePassthrough(underlay)
    monitor = threading.Thread(target=resource_monitor, args=(os.getpid(), 0.02), daemon=True)
    monitor.start()
    print(f"[PURE FUSE] mount={mountpoint} underlay={underlay}")
    print(f"[LOG] latency={LATENCY_CSV}")
    print(f"[LOG] resource={RESOURCE_CSV}")
    print("[MEASURE] logging is initially OFF")
    print(f"[MEASURE] start: touch {LOG_START_FILE}")
    print(f"[MEASURE] stop : touch {LOG_STOP_FILE}")
    print(f"[WORKLOAD] state file: {WORKLOAD_STATE_FILE}")
    pyfuse3.init(ops, mountpoint, set())
    try:
        await pyfuse3.main()
    finally:
        pyfuse3.close(unmount=True)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 pure_fuse_passthrough_logged.py <MOUNTPOINT> <UNDERLAY>")
        raise SystemExit(2)
    trio.run(main, sys.argv[1], sys.argv[2])