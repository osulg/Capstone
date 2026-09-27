"""
수집 모드(--collect-only) 전용 FUSE 이벤트 로거.

eBPF 수집기와 공유하는 스키마로 한 줄에 이벤트 하나를 JSONL로 기록한다.
    ts_ns    : CLOCK_MONOTONIC ns (eBPF bpf_ktime_get_ns()와 같은 시계)
    source   : "fuse"
    run_id   : 수집 세션 ID
    pid      : TGID (FUSE가 주는 값은 TID이므로 /proc에서 정규화)
    tid      : FUSE 요청의 TID
    ppid     : 부모 PID
    comm     : 프로세스 이름
    op       : 대문자 연산명 (OPEN / CREATE / READ / WRITE / RENAME / UNLINK / TRUNCATE ...)
    path     : 마운트 루트 기준 경로
    new_path : RENAME 대상 경로
    size     : READ / WRITE / TRUNCATE 바이트 수
    offset   : READ / WRITE 오프셋
    entropy  : WRITE 버퍼 앞 ENTROPY_HEADER_SIZE 바이트의 Shannon 엔트로피
"""

import json
import os
import re
import socket
import time
import uuid

SCHEMA_VERSION = 1

RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")

_OP_NAMES = {"ftruncate": "TRUNCATE"}
_SIZED_OPS = {"read", "write", "truncate", "ftruncate"}


def new_run_id() -> str:
    return f"{time.strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:6]}"


def read_proc_identity(tid: int):
    """(tgid, ppid, comm). 프로세스가 이미 사라졌으면 (tid, None, None)."""
    try:
        with open(f"/proc/{tid}/status", encoding="utf-8", errors="replace") as f:
            fields = dict(
                line.rstrip("\n").split(":\t", 1)
                for line in f
                if ":\t" in line
            )
        return int(fields["Tgid"]), int(fields["PPid"]), fields["Name"]
    except (OSError, KeyError, ValueError):
        return tid, None, None


class FuseCollectLogger:
    def __init__(self, log_dir: str, run_id: str, mountpoint: str, underlay: str):
        if not RUN_ID_PATTERN.match(run_id):
            raise ValueError(f"run_id에 허용되지 않는 문자가 있습니다: {run_id!r}")

        os.makedirs(log_dir, exist_ok=True)

        self.run_id = run_id
        self.log_path = os.path.join(log_dir, f"{run_id}.fuse.jsonl")
        self.meta_path = os.path.join(log_dir, f"{run_id}.meta.json")

        self._root = os.path.realpath(underlay)
        self._identity_cache = {}

        # 같은 run_id로 이어 쓰면 서로 다른 실행이 한 샘플로 섞이므로 거부한다.
        self._f = open(self.log_path, "x", buffering=1, encoding="utf-8")

        self._meta = {
            "schema_version": SCHEMA_VERSION,
            "source": "fuse",
            "run_id": run_id,
            "mountpoint": os.path.realpath(mountpoint),
            "underlay": self._root,
            "hostname": socket.gethostname(),
            "kernel": os.uname().release,
            "start_wall": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "start_monotonic_ns": time.monotonic_ns(),
            "end_wall": None,
            "end_monotonic_ns": None,
            "events": 0,
        }
        self._write_meta()

    def _write_meta(self) -> None:
        with open(self.meta_path, "w", encoding="utf-8") as f:
            json.dump(self._meta, f, indent=2)

    def _identity(self, tid: int):
        if tid <= 0:
            return tid, None, None

        # FUSE 요청 시점에는 호출 프로세스가 살아 있으므로 첫 조회를 캐시한다.
        # release 등 나중 이벤트는 프로세스가 이미 종료됐을 수 있다.
        ident = self._identity_cache.get(tid)
        if ident is None:
            ident = read_proc_identity(tid)
            self._identity_cache[tid] = ident
        return ident

    def _rel(self, path):
        if path is None:
            return None
        if path == self._root:
            return "/"
        if path.startswith(self._root + os.sep):
            return path[len(self._root):]
        return path

    def write(self, ev) -> None:
        tgid, ppid, comm = self._identity(ev.pid)

        record = {
            "ts_ns": time.monotonic_ns(),
            "source": "fuse",
            "run_id": self.run_id,
            "pid": tgid,
            "tid": ev.pid,
            "ppid": ppid,
            "comm": comm,
            "op": _OP_NAMES.get(ev.op, ev.op.upper()),
            "path": self._rel(ev.path),
            "new_path": self._rel(ev.new_path),
            "size": ev.size if ev.op in _SIZED_OPS else None,
            "offset": ev.off if ev.off >= 0 else None,
            "entropy": round(ev.entropy, 4) if ev.entropy is not None else None,
        }

        self._f.write(json.dumps(record) + "\n")
        self._meta["events"] += 1

    def close(self) -> None:
        self._f.close()
        self._meta["end_wall"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        self._meta["end_monotonic_ns"] = time.monotonic_ns()
        self._write_meta()
