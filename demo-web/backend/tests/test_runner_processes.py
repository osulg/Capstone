"""Run from repository root with unittest discover -s demo-web/backend/tests.

Runtime checks require the backend's existing Pydantic 2 environment.
No dependencies are installed by these tests.
"""

import ast
import importlib.util
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(BACKEND))

from scenario_fixtures import NormalScenarioMixin

HAS_PYDANTIC = importlib.util.find_spec("pydantic") is not None
if HAS_PYDANTIC:
    from app.schemas.run import RunResponse
    from app.services.runner import ScenarioRunner, now


def proc_stat(parent=100, ticks=1234):
    return "200 (worker name) " + " ".join(
        ["S", str(parent)] + ["0"] * 17 + [str(ticks)]
    )


class RunnerStructureTests(unittest.TestCase):
    def test_registration_is_a_class_method(self):
        tree = ast.parse(
            (BACKEND / "app/services/runner.py").read_text(encoding="utf-8")
        )
        cls = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "ScenarioRunner"
        )
        methods = {
            node.name: node
            for node in cls.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        self.assertIn("_register_process", methods)
        self.assertIn("_read_progress", methods)
        self.assertFalse(
            any(
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node is not methods["_read_progress"]
                for node in ast.walk(methods["_read_progress"])
            )
        )


@unittest.skipUnless(HAS_PYDANTIC, "Pydantic is not installed")
class ProcessRegistrationTests(unittest.TestCase):
    def setUp(self):
        self.record = RunResponse(
            run_id="test",
            scenario_id="S01",
            status="running",
            pid=100,
            created_at=now(),
        )
        self.payload = {
            "role": "normal_worker",
            "pid": 200,
            "start_time_ticks": 1234,
            "registered_at": now(),
        }

    def test_direct_child_registration_and_duplicate(self):
        with patch("pathlib.Path.read_text", return_value=proc_stat()):
            ScenarioRunner._register_process(self.record, self.payload)
            ScenarioRunner._register_process(self.record, self.payload)
        self.assertEqual(len(self.record.processes), 1)
        self.assertEqual(self.record.processes[0].pid, 200)

    def test_registration_records_role_for_dashboard(self):
        import json
        import tempfile

        from app.services import runner

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "roles.jsonl"
            with (patch.object(runner, "PROCESS_ROLES_PATH", str(target)),
                  patch("pathlib.Path.read_text", return_value=proc_stat())):
                ScenarioRunner._register_process(self.record, self.payload)
                ScenarioRunner._register_process(self.record, self.payload)  # 중복은 다시 쓰지 않음
            lines = target.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])
        self.assertEqual((entry["pid"], entry["start_time_ticks"], entry["role"], entry["scenario_id"]),
                         (200, 1234, "normal_worker", "S01"))

    def test_self_registration(self):
        self.payload["pid"] = 100
        with patch("pathlib.Path.read_text", return_value=proc_stat(parent=50)):
            ScenarioRunner._register_process(self.record, self.payload)
        self.assertEqual(self.record.processes[0].pid, 100)

    def test_unrelated_process_is_rejected(self):
        with patch("pathlib.Path.read_text", return_value=proc_stat(parent=999)):
            with self.assertRaises(ValueError):
                ScenarioRunner._register_process(self.record, self.payload)
        self.assertFalse(self.record.processes)

    def test_reused_pid_is_rejected(self):
        with patch("pathlib.Path.read_text", return_value=proc_stat(ticks=9999)):
            with self.assertRaises(ValueError):
                ScenarioRunner._register_process(self.record, self.payload)
        self.assertFalse(self.record.processes)


@unittest.skipUnless(HAS_PYDANTIC, "Pydantic is not installed")
class RunnerCleanupTests(NormalScenarioMixin, unittest.IsolatedAsyncioTestCase):
    async def test_output_error_does_not_lock_finished_process(self):
        process = SimpleNamespace(pid=100, returncode=1)
        runner = ScenarioRunner()
        with (
            patch(
                "app.services.runner.asyncio.create_subprocess_exec",
                new=AsyncMock(return_value=process),
            ),
            patch.object(
                runner,
                "_collect_output",
                new=AsyncMock(side_effect=ValueError("invalid progress")),
            ),
            patch.object(
                runner,
                "_terminate_process_group",
                new=AsyncMock(),
            ) as terminate_group,
            self.assertLogs("app.services.runner", level="WARNING"),
        ):
            created = runner.start("S01")
            await runner._active_task
        # 이 검사는 출력 오류와 실행 잠금의 관계만 다룬다.
        # 가짜 PID를 실제 OS 조회나 종료 신호에 사용하지 않는다.
        terminate_group.assert_awaited_once_with(process)
        result = runner.get(created.run_id)
        self.assertEqual(result.status, "failed")
        self.assertIn("invalid progress", result.error)
        self.assertFalse(runner._cleanup_blocked)
        await runner.close()

    async def test_group_cleanup_failure_blocks_new_runs(self):
        process = SimpleNamespace(pid=100, returncode=1)
        runner = ScenarioRunner()
        with (
            patch(
                "app.services.runner.asyncio.create_subprocess_exec",
                new=AsyncMock(return_value=process),
            ),
            patch.object(
                runner,
                "_collect_output",
                new=AsyncMock(side_effect=ValueError("invalid progress")),
            ),
            patch.object(
                runner,
                "_terminate_process_group",
                new=AsyncMock(side_effect=TimeoutError("group still exists")),
            ),
            self.assertLogs("app.services.runner", level="WARNING"),
        ):
            created = runner.start("S01")
            await runner._active_task

        result = runner.get(created.run_id)
        self.assertEqual(result.status, "failed")
        self.assertIn("group still exists", result.error)
        self.assertTrue(runner._cleanup_blocked)
        from app.services.runner import RunBusyError

        with self.assertRaises(RunBusyError):
            runner.start("S01")
        await runner.close()


if __name__ == "__main__":
    unittest.main()
