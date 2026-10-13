"""
eBPF 원시 이벤트를 FUSE 로그와 같은 스키마(v1) 레코드로 변환한다.

BCC에 의존하지 않는 순수 로직이라 단위 테스트가 가능하다.
커널은 fd 번호와 호출 시점의 원시 경로만 주므로, 여기서
프로세스별 fd 테이블 / 작업 디렉터리 / fork 부모를 추적해
READ·WRITE의 대상 파일과 상대 경로를 복원한다.
"""

import os

SCHEMA_VERSION = 1

# ebpf_collector.c에 cflags(-DOP_*)로 주입된다. 값은 C와 공유된다.
OPS = {
    "OP_OPEN": 1,
    "OP_CREATE": 2,
    "OP_OPENDIR": 3,
    "OP_READ": 4,
    "OP_WRITE": 5,
    "OP_COPY": 6,
    "OP_RENAME": 7,
    "OP_UNLINK": 8,
    "OP_RMDIR": 9,
    "OP_MKDIR": 10,
    "OP_TRUNCATE": 11,
    "OP_CHMOD": 12,
    "OP_FORK": 13,
    "OP_EXEC": 14,
    "OP_EXIT": 15,
    "OP_CRYPTO": 16,
    "OP_CLOSE": 17,
    "OP_DUP": 18,
    "OP_CHDIR": 19,
}
OP_NAMES = {code: name[3:] for name, code in OPS.items()}

AT_FDCWD = -100
O_CLOEXEC = 0o2000000
F_DUPFD_CLOEXEC = 1030


class Proc:
    __slots__ = ("ppid", "cwd", "fds", "cloexec", "fork_record")

    def __init__(self, ppid, cwd, fds=None, cloexec=None, fork_record=None):
        self.ppid = ppid
        self.cwd = cwd
        self.fds = fds if fds is not None else {}
        self.cloexec = cloexec if cloexec is not None else set()
        # fork 시점에는 스레드인지 프로세스인지 알 수 없어서, 자식이
        # 자기 TGID로 처음 관측될 때 FORK 레코드를 기록한다.
        self.fork_record = fork_record

    def copy_for_child(self, ppid, fork_record):
        return Proc(ppid, self.cwd, dict(self.fds), set(self.cloexec), fork_record)


class EbpfEventProcessor:
    def __init__(self, run_id: str, target_dir: str, write_record):
        self.run_id = run_id
        self.target = os.path.realpath(target_dir)
        self._write = write_record
        self.procs = {}
        self.events = 0

    def seed_root(self, pid: int, ppid: int, cwd: str) -> None:
        self.procs[pid] = Proc(ppid, cwd)

    # ------------------------------------------------------------ paths

    def _resolve(self, proc, dirfd, raw):
        if not raw:
            return None
        if raw.startswith("/"):
            return os.path.normpath(raw)

        base = proc.cwd if dirfd == AT_FDCWD else proc.fds.get(dirfd)
        if base is None:
            return raw
        return os.path.normpath(os.path.join(base, raw))

    def _scope(self, path):
        """(마운트 기준 경로 또는 원래 경로, in_target)"""
        if path is None:
            return None, None
        if path == self.target:
            return "/", True
        if path.startswith(self.target + os.sep):
            return path[len(self.target):], True
        return path, False

    # ------------------------------------------------------------ output

    def _emit(self, ev, proc, op, path=None, new_path=None, size=None, offset=None):
        rel, in_target = self._scope(path)
        new_rel, new_in_target = self._scope(new_path)

        if in_target is None:
            in_target = new_in_target

        record = {
            "ts_ns": ev["ts_ns"],
            "source": "ebpf",
            "run_id": self.run_id,
            "pid": ev["tgid"],
            "tid": ev["tid"],
            "ppid": proc.ppid if proc else None,
            "comm": ev["comm"],
            "op": op,
            "path": rel,
            "new_path": new_rel,
            "size": size,
            "offset": offset,
            "entropy": None,
            "in_target": bool(in_target) or bool(new_in_target),
        }
        self._write(record)
        self.events += 1

    def _proc_for(self, ev):
        """TGID의 Proc. 새 프로세스로 처음 관측되면 보류해둔 FORK를 먼저 기록한다."""
        proc = self.procs.get(ev["tgid"])

        if proc is None:
            proc = Proc(None, None)
            self.procs[ev["tgid"]] = proc

        if proc.fork_record is not None:
            self._write(proc.fork_record)
            self.events += 1
            proc.fork_record = None

        return proc

    # ------------------------------------------------------------ dispatch

    def handle(self, ev: dict) -> None:
        op = OP_NAMES.get(ev["op"])
        if op is None:
            return

        if op == "FORK":
            self._on_fork(ev)
            return

        if op == "EXIT" and ev["tid"] != ev["tgid"]:
            # 스레드 종료: fork 때 만든 복사본만 정리한다.
            self.procs.pop(ev["tid"], None)
            return

        proc = self._proc_for(ev)
        getattr(self, f"_on_{op.lower()}")(ev, proc)

    def _on_fork(self, ev):
        parent = self.procs.get(ev["tgid"]) or Proc(None, None)
        child_pid = ev["fd"]

        fork_record = {
            "ts_ns": ev["ts_ns"],
            "source": "ebpf",
            "run_id": self.run_id,
            "pid": child_pid,
            "tid": child_pid,
            "ppid": ev["tgid"],
            "comm": ev["comm"],
            "op": "FORK",
            "path": None,
            "new_path": None,
            "size": None,
            "offset": None,
            "entropy": None,
            "in_target": False,
        }
        self.procs[child_pid] = parent.copy_for_child(ev["tgid"], fork_record)

    def _on_exec(self, ev, proc):
        for fd in proc.cloexec:
            proc.fds.pop(fd, None)
        proc.cloexec.clear()
        self._emit(ev, proc, "EXEC", path=ev["path"] or None)

    def _on_exit(self, ev, proc):
        self._emit(ev, proc, "EXIT")
        self.procs.pop(ev["tgid"], None)

    def _on_crypto(self, ev, proc):
        self._emit(ev, proc, "CRYPTO")

    def _open_like(self, ev, proc, op):
        path = self._resolve(proc, ev["fd2"], ev["path"])
        fd = ev["ret"]

        proc.fds[fd] = path
        if ev["flags"] & O_CLOEXEC:
            proc.cloexec.add(fd)
        else:
            proc.cloexec.discard(fd)

        self._emit(ev, proc, op, path=path)

    def _on_open(self, ev, proc):
        self._open_like(ev, proc, "OPEN")

    def _on_create(self, ev, proc):
        self._open_like(ev, proc, "CREATE")

    def _on_opendir(self, ev, proc):
        self._open_like(ev, proc, "OPENDIR")

    def _on_close(self, ev, proc):
        proc.fds.pop(ev["fd"], None)
        proc.cloexec.discard(ev["fd"])

    def _on_dup(self, ev, proc):
        new_fd = ev["ret"]
        path = proc.fds.get(ev["fd2"])

        if path is None:
            proc.fds.pop(new_fd, None)
        else:
            proc.fds[new_fd] = path

        if ev["flags"] & O_CLOEXEC or ev["flags"] == F_DUPFD_CLOEXEC:
            proc.cloexec.add(new_fd)
        else:
            proc.cloexec.discard(new_fd)

    def _on_chdir(self, ev, proc):
        if ev["path"]:
            new_cwd = self._resolve(proc, AT_FDCWD, ev["path"])
        else:
            new_cwd = proc.fds.get(ev["fd"])

        if new_cwd is not None:
            proc.cwd = new_cwd

    def _fd_io(self, ev, proc, op, fd):
        # 파일이 아닌 fd(파이프, 소켓, 추적 전부터 열려 있던 표준 입출력)는 제외한다.
        # 0바이트(EOF) 호출은 FUSE에 요청이 가지 않으므로 비교 가능하도록 뺀다.
        path = proc.fds.get(fd)
        if path is None or ev["ret"] == 0:
            return
        offset = ev["offset"] if ev["offset"] >= 0 else None
        self._emit(ev, proc, op, path=path, size=ev["ret"], offset=offset)

    def _on_read(self, ev, proc):
        self._fd_io(ev, proc, "READ", ev["fd"])

    def _on_write(self, ev, proc):
        self._fd_io(ev, proc, "WRITE", ev["fd"])

    def _on_copy(self, ev, proc):
        # sendfile / copy_file_range: fd2 → fd 로 ret 바이트 복사
        self._fd_io(ev, proc, "READ", ev["fd2"])
        self._fd_io(ev, proc, "WRITE", ev["fd"])

    def _path_or_fd(self, ev, proc):
        if ev["path"]:
            return self._resolve(proc, ev["fd2"], ev["path"])
        return proc.fds.get(ev["fd"])

    def _on_truncate(self, ev, proc):
        path = self._path_or_fd(ev, proc)
        if path is not None:
            self._emit(ev, proc, "TRUNCATE", path=path, size=ev["size"])

    def _on_chmod(self, ev, proc):
        path = self._path_or_fd(ev, proc)
        if path is not None:
            self._emit(ev, proc, "CHMOD", path=path)

    def _on_unlink(self, ev, proc):
        self._emit(ev, proc, "UNLINK", path=self._resolve(proc, ev["fd2"], ev["path"]))

    def _on_rmdir(self, ev, proc):
        self._emit(ev, proc, "RMDIR", path=self._resolve(proc, ev["fd2"], ev["path"]))

    def _on_mkdir(self, ev, proc):
        self._emit(ev, proc, "MKDIR", path=self._resolve(proc, ev["fd2"], ev["path"]))

    def _on_rename(self, ev, proc):
        old = self._resolve(proc, ev["fd2"], ev["path"])
        new = self._resolve(proc, ev["fd"], ev["path2"])

        # 열려 있는 fd가 가리키는 경로도 함께 옮긴다. (이후 WRITE가 새 이름으로 기록되도록)
        if old and new:
            old_prefix = old + os.sep
            for other in self.procs.values():
                for fd, p in list(other.fds.items()):
                    if p == old or (p and p.startswith(old_prefix)):
                        other.fds[fd] = new + p[len(old):]

        self._emit(ev, proc, "RENAME", path=old, new_path=new)
