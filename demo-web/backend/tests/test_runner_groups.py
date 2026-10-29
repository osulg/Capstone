"""Linux 실제 프로세스로 실행 그룹 정리를 검사한다. FUSE는 사용하지 않는다."""

import asyncio
import ctypes
import importlib.util
import json
import os
import signal
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(BACKEND))

HAS_PYDANTIC = importlib.util.find_spec("pydantic") is not None
if HAS_PYDANTIC:
    from app.services.runner import ScenarioRunner


CHILD_CODE = """
import os
import signal
import sys
import time

mode = sys.argv[1]
if mode == "ignore":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
print("READY", flush=True)
if mode == "stopped":
    os.kill(os.getpid(), signal.SIGSTOP)
while True:
    time.sleep(1)
"""

MANAGER_CODE = """
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

mode = sys.argv[1]
child = subprocess.Popen(
    [sys.executable, "-u", "-c", sys.argv[2], mode],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True,
)
if child.stdout.readline().strip() != "READY":
    raise RuntimeError("자식 준비 실패")
child.stdout.close()

def finish(signum, frame):
    # 그룹 신호를 받은 자식의 종료를 회수한다.
    # SIGTERM 무시 모드에서는 부모도 여기서 기다리므로 강제 종료가 필요하다.
    child.wait()
    raise SystemExit(0)

signal.signal(signal.SIGTERM, finish)
if mode == "stopped":
    deadline = time.monotonic() + 5
    while True:
        fields = Path(f"/proc/{child.pid}/stat").read_text().rsplit(")", 1)[1].split()
        if fields[0] == "T":
            break
        if time.monotonic() > deadline:
            raise RuntimeError("자식 정지 상태 확인 실패")
        time.sleep(0.01)

print(json.dumps({"child_pid": child.pid}), flush=True)
if mode == "orphan":
    raise SystemExit(0)
while True:
    time.sleep(1)
"""


@unittest.skipUnless(
    sys.platform == "linux" and HAS_PYDANTIC,
    "Linux와 백엔드 Pydantic 환경이 필요합니다.",
)
class RunnerGroupTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.groups = []
        self.child_pids = set()
        self.runners = []
        self.spawn = asyncio.create_subprocess_exec

        # 고아 프로세스를 테스트가 회수한다. 컨테이너/VM의 PID 1이
        # 좀비를 즉시 회수하는지에 테스트 결과가 의존하지 않도록 한다.
        # 관리자 PID는 asyncio가 회수하고, 알려진 작업 자식만 waitpid한다.
        self.libc = ctypes.CDLL(None, use_errno=True)
        previous = ctypes.c_int()
        self._prctl(37, ctypes.byref(previous))  # PR_GET_CHILD_SUBREAPER
        self.previous_subreaper = previous.value
        self._prctl(36, 1)  # PR_SET_CHILD_SUBREAPER
        self.reaper = asyncio.create_task(self._reap_orphans())

    def _prctl(self, operation, value):
        if self.libc.prctl(operation, value, 0, 0, 0) != 0:
            number = ctypes.get_errno()
            raise OSError(number, os.strerror(number))

    async def _reap_orphans(self):
        while True:
            for pid in tuple(self.child_pids):
                try:
                    reaped, _ = os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    # 아직 관리자의 자식이거나 이미 관리자가 회수했다.
                    continue
                if reaped:
                    self.child_pids.discard(pid)
            await asyncio.sleep(0.01)

    def _runner(self, timeout_seconds=10):
        runner = ScenarioRunner(
            timeout_seconds=timeout_seconds,
            cleanup_seconds=1,
        )
        self.runners.append(runner)
        return runner

    async def _spawn_group(self, mode="normal"):
        manager = await self.spawn(
            sys.executable, "-u", "-c", MANAGER_CODE, mode, CHILD_CODE,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        self.groups.append(manager)
        line = await asyncio.wait_for(manager.stdout.readline(), timeout=5)
        metadata = json.loads(line)
        child_pid = metadata["child_pid"]
        self.child_pids.add(child_pid)
        return manager, child_pid

    def _assert_gone(self, manager, child_pid):
        self.assertIsNotNone(manager.returncode)
        self.assertFalse(ScenarioRunner._group_exists(manager.pid))
        self.assertFalse(Path(f"/proc/{child_pid}").exists())

    async def test_manager_and_child_exit(self):
        manager, child_pid = await self._spawn_group()
        runner = self._runner()
        await runner._terminate_process_group(manager)
        self._assert_gone(manager, child_pid)

    async def test_child_is_cleaned_after_manager_exits(self):
        manager, child_pid = await self._spawn_group("orphan")
        await asyncio.wait_for(manager.wait(), timeout=5)
        self.assertTrue(Path(f"/proc/{child_pid}").exists())
        runner = self._runner()
        await runner._terminate_process_group(manager)
        self._assert_gone(manager, child_pid)

    async def test_sigterm_ignored_escalates_to_sigkill(self):
        manager, child_pid = await self._spawn_group("ignore")
        runner = self._runner()
        with patch.object(
            runner, "_signal_group", wraps=runner._signal_group,
        ) as send_signal:
            await runner._terminate_process_group(manager)
        self.assertIn(
            (manager.pid, signal.SIGKILL),
            [call.args for call in send_signal.call_args_list],
        )
        self._assert_gone(manager, child_pid)

    async def test_stopped_child_is_resumed_and_terminated(self):
        manager, child_pid = await self._spawn_group("stopped")
        runner = self._runner()
        with patch.object(
            runner, "_signal_group", wraps=runner._signal_group,
        ) as send_signal:
            await runner._terminate_process_group(manager)
        calls = [call.args for call in send_signal.call_args_list]
        self.assertIn((manager.pid, signal.SIGCONT), calls)
        self.assertNotIn((manager.pid, signal.SIGKILL), calls)
        self._assert_gone(manager, child_pid)

    async def test_unrelated_group_survives(self):
        target, child_pid = await self._spawn_group()
        other, other_child = await self._spawn_group()
        runner = self._runner()
        await runner._terminate_process_group(target)
        self._assert_gone(target, child_pid)
        self.assertIsNone(other.returncode)
        self.assertEqual(os.getpgid(other_child), other.pid)
        # 별도 그룹도 테스트 종료 전에 명시적으로 회수한다.
        await runner._terminate_process_group(other)
        self._assert_gone(other, other_child)

    async def _check_runner_stop(self, shutdown):
        runner = self._runner(timeout_seconds=0.2 if not shutdown else 10)
        spawned = asyncio.Event()
        captured = {}

        async def create_test_process(*args, **kwargs):
            # S01 대신 무해한 대기 프로그램을 실행한다. 종료 처리는 실제 코드다.
            manager, child_pid = await self._spawn_group()
            captured.update(manager=manager, child_pid=child_pid)
            spawned.set()
            return manager

        with patch(
            "app.services.runner.asyncio.create_subprocess_exec",
            side_effect=create_test_process,
        ):
            created = runner.start("S01")
            await asyncio.wait_for(spawned.wait(), timeout=6)
            if shutdown:
                await asyncio.wait_for(runner.close(), timeout=8)
            else:
                await asyncio.wait_for(
                    asyncio.shield(runner._active_task), timeout=8,
                )

        result = runner.get(created.run_id)
        self.assertEqual(result.status, "failed" if shutdown else "timed_out")
        if shutdown:
            self.assertIn("서버 종료", result.error)
        self.assertFalse(runner._cleanup_blocked)
        self._assert_gone(captured["manager"], captured["child_pid"])

    async def test_execution_timeout_cleans_group(self):
        await self._check_runner_stop(shutdown=False)

    async def test_server_close_cleans_group(self):
        await self._check_runner_stop(shutdown=True)

    async def asyncTearDown(self):
        try:
            # 검사가 실패해도 이 테스트가 생성한 독립 그룹만 정리한다.
            for manager in self.groups:
                try:
                    os.killpg(manager.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            for manager in self.groups:
                await asyncio.wait_for(manager.wait(), timeout=5)
                if manager.stdin is not None:
                    manager.stdin.close()
            for runner in self.runners:
                await asyncio.wait_for(runner.close(), timeout=8)
            for manager in self.groups:
                await asyncio.wait_for(manager.stdout.read(), timeout=5)
                await asyncio.wait_for(manager.stderr.read(), timeout=5)

            # 고아가 된 자식의 종료 상태까지 회수할 시간을 준다.
            deadline = asyncio.get_running_loop().time() + 3
            while any(Path(f"/proc/{pid}").exists() for pid in self.child_pids):
                if asyncio.get_running_loop().time() >= deadline:
                    self.fail("테스트 자식의 종료 상태를 회수하지 못했습니다.")
                await asyncio.sleep(0.02)
        finally:
            self.reaper.cancel()
            await asyncio.gather(self.reaper, return_exceptions=True)
            self._prctl(36, self.previous_subreaper)


if __name__ == "__main__":
    unittest.main()
