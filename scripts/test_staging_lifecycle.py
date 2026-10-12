"""MEDIUM 신규 파일 staging 생명주기와 강제 상태 보호를 검증하는 회귀 테스트.

실행 방법: python3 scripts/test_staging_lifecycle.py

총 12개 검사:
- 생명주기 5개: close 후/열린 핸들 상태에서 commit 및 drop 처리,
  commit 목적지 충돌 시 기존 파일과 recovery 데이터 보존.
  실제 MEDIUM 정책 함수와 임시 파일로 데이터 반영/폐기, staging 정리,
  inode/핸들 상태 및 버퍼 자원 정리를 확인한다.
- 상태 보호 7개: override 중 자동 상태 변경 차단, 해제 후 상태 변경,
  HIGH 강등 방지, 오래된 강제 HIGH 적용 차단, 잠금 대기 중 override 변경,
  MEDIUM 재평가 목록/시작 시간 유지, 강제 HIGH 처리 경로 호출 확인.

실제 FUSE mount를 통과하지 않는다. 필요한 메서드를 원본 코드에서 추출하고
가짜 객체를 사용하므로 전체 worker 루프, ML 평가, 실제 프로세스 종료 및
재시작 복구는 검증하지 않는다. mount 동작은 별도 회귀 테스트로 확인한다.

상태 보호 검사는 FUSE/ML 의존성 없이 실행한다. 생명주기 검사는 Linux와
프로젝트의 Trio 환경이 필요하며, 해당 조건을 충족하지 않으면 건너뛴다.
"""

from __future__ import annotations

import ast
import asyncio
import os
import sys
import tempfile
import time
import unittest
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from guardfs.stage2.states import ProcState


def load_methods(names, namespace):
    tree = ast.parse(
        (ROOT / "guardfs/fuse_fs/passthrough.py").read_text(encoding="utf-8")
    )
    cls = next(
        n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Passthrough"
    )
    nodes = [
        n
        for n in cls.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in names
    ]
    module = ast.Module(
        body=[
            ast.ImportFrom(
                module="__future__", names=[ast.alias(name="annotations")], level=0
            ),
            *nodes,
        ],
        type_ignores=[],
    )
    exec(
        compile(
            ast.fix_missing_locations(module), "<actual Passthrough methods>", "exec"
        ),
        namespace,
    )
    return namespace


class Lock:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


STATE_NS = load_methods(
    {"set_proc_state"},
    {"ProcState": ProcState, "trio": SimpleNamespace(current_time=lambda: 12.0)},
)


class StateOps:
    set_proc_state = STATE_NS["set_proc_state"]

    def __init__(self):
        self._pid_lock = Lock()
        self._proc_state = {42: ProcState.MEDIUM}
        self._medium_pids = {42: 1.0}
        self.forced = ProcState.MEDIUM
        self.high_calls = []

    def _get_forced_state(self, pid):
        return self.forced

    async def trigger_high(self, pid, reason="", **kwargs):
        if await self.set_proc_state(pid, ProcState.HIGH, **kwargs):
            self.high_calls.append(pid)


def worker_helpers(ops):
    tree = ast.parse(
        (ROOT / "guardfs/stage2/stage2_worker.py").read_text(encoding="utf-8")
    )
    worker = next(
        n
        for n in tree.body
        if isinstance(n, ast.AsyncFunctionDef) and n.name == "stage2_worker"
    )
    nodes = [
        n
        for n in worker.body
        if isinstance(n, ast.AsyncFunctionDef)
        and n.name in {"defer_forced_state", "discard_if_high"}
    ]
    ns = {
        "ops": ops,
        "medium_lock": ops._pid_lock,
        "medium_pids": ops._medium_pids,
        "watch_pids": {},
        "ProcState": ProcState,
        "trio": SimpleNamespace(current_time=lambda: 12.0),
    }
    exec(
        compile(
            ast.Module(body=nodes, type_ignores=[]), "<actual worker helpers>", "exec"
        ),
        ns,
    )
    return ns


class StateTests(unittest.TestCase):
    def test_override_blocks_automatic_low_medium_high(self):
        for forced in (ProcState.LOW, ProcState.MEDIUM, ProcState.HIGH):
            for target in (ProcState.LOW, ProcState.MEDIUM, ProcState.HIGH):
                ops = StateOps()
                ops.forced = forced
                changed = asyncio.run(
                    ops.set_proc_state(42, target, respect_forced=True)
                )
                self.assertFalse(changed)
                self.assertEqual(ops._proc_state[42], ProcState.MEDIUM)
                self.assertIn(42, ops._medium_pids)

    def test_removed_override_allows_low(self):
        ops = StateOps()
        ops.forced = None
        self.assertTrue(
            asyncio.run(ops.set_proc_state(42, ProcState.LOW, respect_forced=True))
        )
        self.assertNotIn(42, ops._medium_pids)

    def test_high_cannot_be_downgraded(self):
        ops = StateOps()
        ops.forced = None
        ops._proc_state[42] = ProcState.HIGH
        self.assertFalse(
            asyncio.run(ops.set_proc_state(42, ProcState.LOW, preserve_high=True))
        )

    def test_stale_forced_high_is_rejected(self):
        ops = StateOps()
        self.assertFalse(
            asyncio.run(
                ops.set_proc_state(42, ProcState.HIGH, expected_forced=ProcState.HIGH)
            )
        )

    def test_override_created_while_waiting_for_lock(self):
        ops = StateOps()
        ops.forced = None

        class ChangedLock(Lock):
            async def __aenter__(self):
                ops.forced = ProcState.MEDIUM
                return self

        ops._pid_lock = ChangedLock()
        self.assertFalse(
            asyncio.run(ops.set_proc_state(42, ProcState.LOW, respect_forced=True))
        )

    def test_medium_deferred_then_resumed_without_timer_reset(self):
        ops = StateOps()
        ns = worker_helpers(ops)
        self.assertTrue(asyncio.run(ns["defer_forced_state"](42)))
        self.assertEqual(ops._medium_pids[42], 1.0)
        ops.forced = None
        self.assertFalse(asyncio.run(ns["defer_forced_state"](42)))
        self.assertIn(42, ops._medium_pids)

    def test_forced_high_enters_high_cleanup_path(self):
        ops = StateOps()
        ops.forced = ProcState.HIGH
        ns = worker_helpers(ops)
        self.assertTrue(asyncio.run(ns["defer_forced_state"](42)))
        self.assertEqual(ops.high_calls, [42])
        self.assertNotIn(42, ops._medium_pids)
        self.assertNotIn(42, ns["watch_pids"])


try:
    import trio
except ModuleNotFoundError:
    trio = None


@unittest.skipUnless(
    sys.platform.startswith("linux") and trio is not None, "requires Linux and Trio"
)
class LifecycleTests(unittest.TestCase):
    def scenario(self, action, close_before):
        from guardfs.stage2.policy import medium

        namespace = load_methods(
            {
                "release",
                "_finish_staging_commit",
                "_finish_staging_drop",
                "_finish_staging_recovery",
            },
            {"os": os, "time": time, "FsEvent": lambda **kwargs: kwargs},
        )

        class Ops:
            release = namespace["release"]
            _finish_staging_commit = namespace["_finish_staging_commit"]
            _finish_staging_drop = namespace["_finish_staging_drop"]
            _finish_staging_recovery = namespace["_finish_staging_recovery"]

            def is_trusted_process(self, pid):
                return False

            def _emit(self, event):
                pass

            async def trigger_high(self, pid, reason=""):
                raise AssertionError(f"unexpected HIGH: {reason}")

        async def run(root):
            ops = Ops()
            for name in (
                "_write_buffer",
                "_staging_pid",
                "_staging_recovery",
                "_unlink_staged",
                "_unlink_recovery",
                "_rmdir_staged",
                "_pending_metadata",
            ):
                setattr(ops, name, defaultdict(list))
            for name in ("_buffer_fds", "_buffer_new_files"):
                setattr(ops, name, defaultdict(dict))
            for name in (
                "_medium_entered_at",
                "_pid_trusted",
                "_staging_origin_fd",
                "_staging_fh",
                "_fh_info",
                "_fd_map",
                "_fh_inode",
                "_inode_path",
                "_inode_alias",
                "_staging_inodes",
                "_unlink_identity",
                "_rmdir_identity",
            ):
                setattr(ops, name, {})
            ops._write_buffer_bytes = defaultdict(int)
            ops._global_buffer_bytes = 0
            ops._trunc_paths = defaultdict(set)
            target = root / "new.txt"
            staging = root / "fh_1"
            fd = os.open(staging, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            identity = (os.fstat(fd).st_dev, os.fstat(fd).st_ino)
            pid, fh, inode = 4242, 1, 0x80000001
            ops._fd_map[fh] = fd
            ops._fh_info[fh] = (pid, str(target), os.O_RDWR)
            ops._fh_inode[fh] = inode
            ops._inode_path[inode] = str(target)
            ops._staging_fh[fh] = str(staging)
            ops._staging_origin_fd[fd] = None
            ops._staging_pid[pid].append(str(staging))
            held = medium._retain_buffer_fd(pid, fd, ops)
            ops._write_buffer[pid].append((held, 0, None, str(target)))
            ops._staging_inodes[inode] = {
                "pid": pid,
                "state": "pending",
                "source_identity": identity,
                "held_fd": held,
            }
            payload = b"STAGED-DATA\n"
            try:
                with patch.object(medium, "log_medium_event"):
                    await medium.handle_write_medium(
                        fd, 0, payload, str(target), pid, ops
                    )
                    if close_before:
                        await ops.release(fh)
                    self.assertTrue(staging.exists())
                    self.assertFalse(target.exists())
                    if action == "conflict":
                        target.write_bytes(b"EXISTING")
                    if action == "drop":
                        await medium.drop_buffers(pid, ops)
                    else:
                        await medium.commit_buffers(pid, ops)
                entry = ops._staging_inodes[inode]
                if action == "conflict":
                    self.assertEqual(target.read_bytes(), b"EXISTING")
                    self.assertEqual(staging.read_bytes(), payload)
                    self.assertEqual(entry["state"], "recovery")
                    self.assertIn(
                        (str(target), str(staging)), ops._staging_recovery[pid]
                    )
                elif action == "drop":
                    self.assertFalse(target.exists())
                    self.assertFalse(staging.exists())
                    self.assertEqual(entry["state"], "dropped")
                else:
                    self.assertEqual(target.read_bytes(), payload)
                    self.assertFalse(staging.exists())
                    self.assertEqual(entry["state"], "committed")
                    self.assertEqual(
                        ops._inode_alias[(target.stat().st_dev, target.stat().st_ino)],
                        inode,
                    )
                    if not close_before:
                        self.assertEqual(
                            os.pread(ops._fd_map[fh], len(payload), 0), payload
                        )
                self.assertFalse(ops._write_buffer.get(pid))
                self.assertFalse(ops._buffer_fds.get(pid))
                self.assertEqual(ops._global_buffer_bytes, 0)
            finally:
                for live_fh in list(ops._fd_map):
                    await ops.release(live_fh)
                medium._close_buffer_fds(pid, ops)

        with tempfile.TemporaryDirectory(prefix="guardfs-lifecycle-") as tmp:
            trio.run(run, Path(tmp))

    def test_commit_after_release(self):
        self.scenario("commit", True)

    def test_commit_with_open_handle(self):
        self.scenario("commit", False)

    def test_drop_after_release(self):
        self.scenario("drop", True)

    def test_drop_with_open_handle(self):
        self.scenario("drop", False)

    def test_conflict_preserves_recovery_after_release(self):
        self.scenario("conflict", True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
