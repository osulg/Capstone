"""EbpfEventProcessor 단위 테스트 (BCC 불필요): python3 -m pytest models/dynamic/collect"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ebpf_events import AT_FDCWD, O_CLOEXEC, OPS, EbpfEventProcessor  # noqa: E402

TARGET = "/mnt/guard"
ROOT = 100


def make():
    records = []
    proc = EbpfEventProcessor("run1", TARGET, records.append)
    proc.seed_root(ROOT, ppid=1, cwd=TARGET)
    return proc, records


def ev(op, tgid=ROOT, tid=None, ret=0, fd=-1, fd2=AT_FDCWD, path="", path2="",
       flags=0, size=-1, offset=-1, ts=0):
    return {
        "ts_ns": ts, "ret": ret, "size": size, "offset": offset,
        "tgid": tgid, "tid": tgid if tid is None else tid, "op": OPS[f"OP_{op}"],
        "fd": fd, "fd2": fd2, "flags": flags, "comm": "t", "path": path, "path2": path2,
    }


def ops_of(records):
    return [(r["op"], r["path"], r["new_path"]) for r in records]


def test_relative_paths_resolve_against_cwd_and_chdir():
    p, out = make()
    p.handle(ev("CREATE", path="a.txt", ret=3))
    p.handle(ev("CHDIR", path="sub"))
    p.handle(ev("UNLINK", path="../a.txt"))
    p.handle(ev("MKDIR", path="/etc/x"))

    assert ops_of(out) == [
        ("CREATE", "/a.txt", None),
        ("UNLINK", "/a.txt", None),
        ("MKDIR", "/etc/x", None),
    ]
    assert [r["in_target"] for r in out] == [True, True, False]


def test_write_uses_fd_table_and_skips_unknown_and_empty():
    p, out = make()
    p.handle(ev("OPEN", path="f.txt", ret=5))
    p.handle(ev("WRITE", fd=5, ret=10, offset=4))
    p.handle(ev("WRITE", fd=5, ret=0))       # EOF/0바이트
    p.handle(ev("WRITE", fd=1, ret=3))       # 추적 전부터 열린 stdout
    p.handle(ev("CLOSE", fd=5))
    p.handle(ev("WRITE", fd=5, ret=3))       # 닫힌 fd

    writes = [r for r in out if r["op"] == "WRITE"]
    assert [(r["path"], r["size"], r["offset"]) for r in writes] == [("/f.txt", 10, 4)]


def test_dup2_redirect_and_copy_file_range():
    p, out = make()
    p.handle(ev("CREATE", path="out.log", ret=3))
    p.handle(ev("DUP", fd2=3, ret=1))        # dup2(3, 1)
    p.handle(ev("WRITE", fd=1, ret=7))
    p.handle(ev("OPEN", path="src", ret=4))
    p.handle(ev("COPY", fd=3, fd2=4, ret=20))

    io = [(r["op"], r["path"], r["size"]) for r in out if r["op"] in ("READ", "WRITE")]
    assert io == [("WRITE", "/out.log", 7), ("READ", "/src", 20), ("WRITE", "/out.log", 20)]


def test_fork_record_deferred_until_child_seen_and_threads_share_fds():
    p, out = make()
    p.handle(ev("OPEN", path="shared", ret=3))

    # 스레드 생성: 자식 TID 201은 TGID로 관측되지 않는다 → FORK 기록 없음
    p.handle(ev("FORK", fd=201))
    p.handle(ev("WRITE", tid=201, fd=3, ret=5))
    p.handle(ev("EXIT", tid=201))

    # 프로세스 생성: 자식 300이 자기 TGID로 처음 관측될 때 FORK가 먼저 기록된다
    p.handle(ev("FORK", fd=300, ts=1))
    p.handle(ev("WRITE", tgid=300, fd=3, ret=6, ts=2))

    assert [r["op"] for r in out] == ["OPEN", "WRITE", "FORK", "WRITE"]
    thread_write, fork, child_write = out[1], out[2], out[3]
    assert (thread_write["pid"], thread_write["tid"], thread_write["path"]) == (ROOT, 201, "/shared")
    assert (fork["pid"], fork["ppid"]) == (300, ROOT)
    assert (child_write["path"], child_write["ppid"]) == ("/shared", ROOT)
    assert 201 not in p.procs


def test_exec_drops_cloexec_fds():
    p, out = make()
    p.handle(ev("OPEN", path="keep", ret=3))
    p.handle(ev("OPEN", path="drop", ret=4, flags=O_CLOEXEC))
    p.handle(ev("EXEC", path="/usr/bin/tool"))
    p.handle(ev("WRITE", fd=3, ret=1))
    p.handle(ev("WRITE", fd=4, ret=1))

    assert [r["path"] for r in out if r["op"] == "WRITE"] == ["/keep"]


def test_rename_updates_open_fd_paths_and_extension():
    p, out = make()
    p.handle(ev("OPEN", path="doc.pdf", ret=3))
    p.handle(ev("RENAME", path="doc.pdf", path2="doc.pdf.locked", fd2=AT_FDCWD, fd=AT_FDCWD))
    p.handle(ev("WRITE", fd=3, ret=8))

    assert ops_of(out)[1] == ("RENAME", "/doc.pdf", "/doc.pdf.locked")
    assert out[2]["path"] == "/doc.pdf.locked"


def test_exit_removes_process_state():
    p, out = make()
    p.handle(ev("EXIT"))
    assert out[-1]["op"] == "EXIT"
    assert ROOT not in p.procs
