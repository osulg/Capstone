"""최종 JSON 결과와 runner 상태·정리·이벤트 수집의 연결 검사."""

import asyncio
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(BACKEND))

from scenario_fixtures import NORMAL_SCENARIO, NormalScenarioMixin

HAS_PYDANTIC = importlib.util.find_spec("pydantic") is not None
if HAS_PYDANTIC:
    from app.schemas.run import RunEventCollection
    from app.services.runner import ScenarioRunner


@unittest.skipUnless(HAS_PYDANTIC, "백엔드 Pydantic 환경이 필요합니다.")
class RunnerResultTests(NormalScenarioMixin, unittest.IsolatedAsyncioTestCase):
    def make_result(self, status="passed", *, legacy=False):
        names = [
            name for step in NORMAL_SCENARIO.steps for name in step.operation_names
        ]
        if status != "passed":
            names = names[: names.index("WRITE") + 1]

        operations = []
        for name in names:
            failed = status != "passed" and name == "WRITE"
            operation = {
                "name": name,
                "status": "failed" if failed else "passed",
            }
            if not legacy:
                operation.update(
                    planned=12,
                    attempted=3 if failed else 12,
                    completed=2 if failed else 12,
                    failure=None,
                )
                if failed:
                    message = (
                        "쓰기 작업 제한 시간을 초과했습니다."
                        if status == "timed_out"
                        else "쓰기 작업이 거절됐습니다."
                    )
                    operation["error"] = message
                    operation["failure"] = {
                        "operation": "write",
                        "path": "/runtime/mount/test/file.txt",
                        "errno": None if status == "timed_out" else 13,
                        "message": message,
                    }
            operations.append(operation)

        result = {
            "scenario_id": "S01",
            "pid": 123,
            "status": status,
            "steps": operations,
        }
        if not legacy:
            result.update(
                result_version=2,
                termination_reason={
                    "passed": "completed",
                    "failed": "operation_failed",
                    "timed_out": "deadline_exceeded",
                }[status],
            )
        return result

    async def run_result(self, payload):
        runner = ScenarioRunner()
        process = SimpleNamespace(
            pid=123,
            returncode=0 if payload["status"] == "passed" else 1,
        )
        order = []

        async def terminate(*args):
            order.append("cleanup")

        def collect(*args):
            order.append("collect")
            return RunEventCollection(issues=["테스트용 로그 누락"])

        try:
            with (
                patch.object(runner, "_capture_event_logs", return_value=([], [])),
                patch(
                    "app.services.runner.asyncio.create_subprocess_exec",
                    new=AsyncMock(return_value=process),
                ),
                patch.object(
                    runner,
                    "_collect_output",
                    new=AsyncMock(return_value=json.dumps(payload).encode()),
                ),
                patch.object(
                    runner,
                    "_terminate_process_group",
                    new=AsyncMock(side_effect=terminate),
                ) as cleanup,
                patch.object(
                    runner, "_collect_run_events", side_effect=collect
                ) as events,
            ):
                created = runner.start("S01")
                await asyncio.wait_for(runner._active_task, timeout=5)
                record = runner.get(created.run_id)
                cleanup.assert_awaited_once_with(process)
                events.assert_called_once()

            self.assertEqual(order, ["cleanup", "collect"])
            self.assertIsNotNone(record.finished_at)
            self.assertEqual(record.result, payload)
            self.assertEqual(record.event_collection.issues, ["테스트용 로그 누락"])
            self.assertEqual(record.detection_verification, "not_checked")
            return record
        finally:
            await runner.close()

    async def test_version_two_completed_result(self):
        record = await self.run_result(self.make_result())
        self.assertEqual(record.status, "passed")
        self.assertTrue(all(step.status == "passed" for step in record.steps))

    async def test_partial_failure_preserves_details(self):
        record = await self.run_result(self.make_result("failed"))
        self.assertEqual(record.status, "failed")
        self.assertEqual(record.error, "쓰기 작업이 거절됐습니다.")
        self.assertEqual(record.steps[0].status, "failed")
        self.assertTrue(all(step.status == "skipped" for step in record.steps[1:]))

    async def test_work_deadline_preserves_partial_result(self):
        record = await self.run_result(self.make_result("timed_out"))
        self.assertEqual(record.status, "timed_out")
        self.assertEqual(record.error, "쓰기 작업 제한 시간을 초과했습니다.")
        self.assertEqual(record.steps[0].status, "failed")
        self.assertTrue(all(step.status == "skipped" for step in record.steps[1:]))

    async def test_legacy_completed_result(self):
        record = await self.run_result(self.make_result(legacy=True))
        self.assertEqual(record.status, "passed")


if __name__ == "__main__":
    unittest.main()
