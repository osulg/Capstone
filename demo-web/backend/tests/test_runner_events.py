"""실행 수명주기와 읽기 전용 로그 수집의 연결을 검사한다."""

import asyncio
import importlib.util
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(BACKEND))

HAS_PYDANTIC = importlib.util.find_spec("pydantic") is not None
if HAS_PYDANTIC:
    from app.schemas.run import RunEventCollection, RunProcess, RunResponse, RunWorkspace
    from app.services.holdfs_events import EventCollection, capture_log
    from app.services.runner import ScenarioRunner, now
    from scenarios.catalog import get_scenario


@unittest.skipUnless(HAS_PYDANTIC, "백엔드 Pydantic 환경이 필요합니다.")
class RunnerEventTests(unittest.IsolatedAsyncioTestCase):
    def _registered_record(self):
        """파일을 만들지 않고 로그 연결용 실행 정보를 준비한다."""
        return RunResponse(
            run_id="test", scenario_id="S01", status="passed", created_at=now(),
            workspace=RunWorkspace(
                name="s01_test",
                mount_path="/runtime/mount/s01_test",
                underlay_path="/runtime/underlay/s01_test",
            ),
            processes=[RunProcess(
                role="normal_worker", pid=123,
                start_time_ticks=1, registered_at=now(),
            )],
        )

    async def test_real_log_records_are_filtered_and_collected(self):
        runner = ScenarioRunner()
        try:
            with tempfile.TemporaryDirectory() as directory:
                filesystem = Path(directory) / "events.jsonl"
                policy = Path(directory) / "policy.log"
                filesystem.write_text("old record\n", encoding="utf-8")
                policy.write_bytes(b"")
                checkpoints = [
                    capture_log(filesystem, "filesystem"),
                    capture_log(policy, "policy"),
                ]
                started = time.time_ns()
                records = [
                    {"pid": pid, "ts_ns": time.time_ns(), "op": "write",
                     "path": path, "applied": False}
                    for pid, path in (
                        (123, "/runtime/underlay/s01_test/test.txt"),
                        (999, "/runtime/underlay/s01_test/test.txt"),
                        (123, "/runtime/underlay/other/test.txt"),
                    )
                ]
                with filesystem.open("a", encoding="utf-8") as stream:
                    for record in records:
                        stream.write(json.dumps(record) + "\n")
                policy.write_text(
                    "[MEDIUM]\nTime: 2026-11-06 12:00:00\nPID: 123\n"
                    "Target: /runtime/underlay/s01_test/test.txt\n"
                    "Action: COMMIT\nResult: FILE_APPLIED\nReason: test\n\n"
                    "[MEDIUM]\nTime: 2026-11-06 12:00:00\nPID: 123\n"
                    "Target: \nAction: COMMIT\nResult: DATA_APPLIED\nReason: test\n\n",
                    encoding="utf-8",
                )

                report = runner._collect_run_events(
                    self._registered_record(), checkpoints, [], started,
                )
                self.assertEqual(len(report.events), 2)
                self.assertEqual(len(report.pid_only_events), 1)
                self.assertEqual(report.issues, [])
                self.assertFalse(report.pending_record)
                self.assertEqual(report.captured_sources, ["filesystem", "policy"])
        finally:
            await runner.close()

    async def test_one_collection_exception_preserves_other_source(self):
        runner = ScenarioRunner()
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "log"
                path.write_bytes(b"")
                checkpoints = [
                    capture_log(path, "filesystem"),
                    capture_log(path, "policy"),
                ]
                policy_event = {"source": "policy", "pid": 123, "op": "COMMIT"}
                with patch(
                    "app.services.runner.collect_events",
                    side_effect=[
                        ValueError("broken source"),
                        EventCollection(events=[policy_event]),
                    ],
                ), self.assertLogs("app.services.runner", level="ERROR"):
                    report = runner._collect_run_events(
                        self._registered_record(), checkpoints, [], time.time_ns(),
                    )
                self.assertEqual(report.events, [policy_event])
                self.assertTrue(any("broken source" in issue for issue in report.issues))
        finally:
            await runner.close()

    async def _run_success(self, *, capture_failure=False, collect_failure=False):
        runner = ScenarioRunner()
        order = []
        process = SimpleNamespace(pid=123, returncode=0)
        scenario = get_scenario("S01")
        result = {
            "scenario_id": "S01", "pid": 123, "status": "passed",
            "steps": [
                {"name": name, "status": "passed"}
                for step in scenario.steps for name in step.operation_names
            ],
        }

        def capture():
            order.append("capture")
            if capture_failure:
                raise OSError("capture failed")
            return [], ["sample missing log"]

        async def spawn(*args, **kwargs):
            order.append("spawn")
            return process

        async def terminate(*args):
            order.append("terminate")

        def collect(*args):
            order.append("collect")
            if collect_failure:
                raise ValueError("collect failed")
            return RunEventCollection(issues=list(args[2]))

        try:
            with (
                patch.object(runner, "_capture_event_logs", side_effect=capture),
                patch(
                    "app.services.runner.asyncio.create_subprocess_exec",
                    side_effect=spawn,
                ),
                patch.object(
                    runner, "_collect_output",
                    new=AsyncMock(return_value=json.dumps(result).encode()),
                ),
                patch.object(runner, "_terminate_process_group", side_effect=terminate),
                patch.object(runner, "_collect_run_events", side_effect=collect),
            ):
                created = runner.start("S01")
                await asyncio.wait_for(runner._active_task, timeout=5)
            return runner.get(created.run_id), order
        finally:
            await runner.close()

    async def test_capture_precedes_spawn_and_collection_follows_cleanup(self):
        result, order = await self._run_success()
        self.assertEqual(order, ["capture", "spawn", "terminate", "collect"])
        self.assertEqual(result.status, "passed")
        self.assertIsNotNone(result.finished_at)
        self.assertEqual(result.event_collection.issues, ["sample missing log"])
        self.assertEqual(result.detection_verification, "not_checked")

    async def test_capture_error_does_not_fail_file_operations(self):
        with self.assertLogs("app.services.runner", level="ERROR"):
            result, _ = await self._run_success(capture_failure=True)
        self.assertEqual(result.status, "passed")
        self.assertTrue(any(
            "capture failed" in issue for issue in result.event_collection.issues
        ))

    async def test_collection_error_does_not_fail_file_operations(self):
        with self.assertLogs("app.services.runner", level="ERROR"):
            result, _ = await self._run_success(collect_failure=True)
        self.assertEqual(result.status, "passed")
        self.assertTrue(any(
            "collect failed" in issue for issue in result.event_collection.issues
        ))

    async def test_missing_filesystem_log_does_not_skip_policy_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_log = root / "policy.log"
            policy_log.write_bytes(b"")
            runner = ScenarioRunner(underlay_path=root / "underlay")
            try:
                with patch(
                    "app.services.runner.FILESECURITY_LOG_PATH", str(policy_log),
                ):
                    checkpoints, issues = runner._capture_event_logs()
                self.assertEqual([item.source for item in checkpoints], ["policy"])
                self.assertEqual(len(issues), 1)
                self.assertIn("filesystem", issues[0])
            finally:
                await runner.close()

    async def test_terminal_status_is_hidden_until_finalization(self):
        runner = ScenarioRunner()
        record = RunResponse(
            run_id="test", scenario_id="S01", status="passed", created_at=now(),
        )
        runner._runs[record.run_id] = record
        try:
            self.assertEqual(runner.get(record.run_id).status, "running")
            self.assertEqual(record.status, "passed")
            record.event_collection = RunEventCollection()
            record.finished_at = now()
            public = runner.get(record.run_id)
            self.assertEqual(public.status, "passed")
            self.assertIsNotNone(public.event_collection)
        finally:
            await runner.close()

    async def test_cancelled_run_also_collects_events(self):
        runner = ScenarioRunner()
        ready = asyncio.Event()
        exited = asyncio.Event()
        process = SimpleNamespace(pid=123, returncode=None)

        async def output(*args):
            ready.set()
            await exited.wait()
            return b""

        async def terminate(target):
            target.returncode = -15
            exited.set()

        def collect(record, checkpoints, issues, started_at_ns):
            self.assertEqual(record.status, "cancelled")
            self.assertIsNone(record.result)
            self.assertIsNotNone(record.workspace)
            self.assertIsNotNone(started_at_ns)
            return RunEventCollection(issues=["test observation"])

        with (
            patch.object(runner, "_capture_event_logs", return_value=([], [])),
            patch(
                "app.services.runner.asyncio.create_subprocess_exec",
                new=AsyncMock(return_value=process),
            ),
            patch.object(runner, "_collect_output", side_effect=output),
            patch.object(runner, "_terminate_process_group", side_effect=terminate),
            patch.object(runner, "_collect_run_events", side_effect=collect) as collector,
        ):
            try:
                created = runner.start("S01")
                await asyncio.wait_for(ready.wait(), timeout=3)
                runner.cancel(created.run_id)
                await asyncio.wait_for(runner._active_task, timeout=5)
                result = runner.get(created.run_id)
                self.assertEqual(result.status, "cancelled")
                self.assertEqual(result.event_collection.issues, ["test observation"])
                collector.assert_called_once()
            finally:
                exited.set()
                await runner.close()


if __name__ == "__main__":
    unittest.main()
