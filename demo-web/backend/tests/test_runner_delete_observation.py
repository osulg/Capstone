"""로그 삭제 실행의 종료 후 파일 상태 조회 연결 검사."""

import asyncio
import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(BACKEND))

from app.schemas.run import RunEventCollection
from app.services.runner import ScenarioRunner

from scenarios.catalog import get_scenario


class RunnerDeleteObservationTests(unittest.IsolatedAsyncioTestCase):
    async def run_case(self, *, status="passed", observation_error=False):
        original = get_scenario("S03")
        scenario = replace(
            original,
            modes=tuple(
                replace(mode, enabled=True, disabled_reason=None)
                if mode.id == "delete"
                else mode
                for mode in original.modes
            ),
        )

        runner = ScenarioRunner()
        process = SimpleNamespace(
            pid=123,
            returncode=0 if status == "passed" else 1,
        )
        order = []
        observation = {
            "status": "observed",
            "files": [],
            "counts": {},
            "issues": [],
        }
        payload = {
            "scenario_id": "S03",
            "mode": "delete",
            "pid": 123,
            "status": status,
        }

        async def collect_output(*args):
            return json.dumps(payload).encode("utf-8")

        async def cleanup_process(*args):
            order.append("cleanup")

        def collect_events(*args):
            order.append("events")
            return RunEventCollection(issues=[])

        def map_steps(record, definition, result):
            # 단계 매핑 자체는 기존 관리자·runner 검증에서 검사한다.
            for step in record.steps:
                step.status = "passed" if status == "passed" else "failed"

        def observe(record, *, cleanup_confirmed):
            order.append("observation")
            self.assertTrue(cleanup_confirmed)
            self.assertIsNotNone(record.event_collection)
            self.assertIsNone(record.finished_at)
            self.assertEqual(record.mode, "delete")

            if observation_error:
                raise RuntimeError("test observation error")

            return observation

        try:
            with (
                patch(
                    "app.services.runner.get_scenario",
                    return_value=scenario,
                ),
                patch.object(
                    runner,
                    "_capture_event_logs",
                    return_value=([], []),
                ),
                patch(
                    "app.services.runner.asyncio.create_subprocess_exec",
                    new=AsyncMock(return_value=process),
                ),
                patch.object(
                    runner,
                    "_collect_output",
                    new=AsyncMock(side_effect=collect_output),
                ),
                patch.object(
                    runner,
                    "_terminate_process_group",
                    new=AsyncMock(side_effect=cleanup_process),
                ),
                patch.object(
                    runner,
                    "_collect_run_events",
                    side_effect=collect_events,
                ),
                patch.object(
                    runner,
                    "_validate_result",
                    return_value=None,
                ),
                patch.object(
                    runner,
                    "_map_steps",
                    side_effect=map_steps,
                ),
                patch(
                    "app.services.runner.observe_deleted_files",
                    side_effect=observe,
                ) as observe_mock,
            ):
                if observation_error:
                    with self.assertLogs(
                        "app.services.runner",
                        level="ERROR",
                    ):
                        created = runner.start("S03", mode="delete")
                        await asyncio.wait_for(
                            runner._active_task,
                            timeout=5,
                        )
                else:
                    created = runner.start("S03", mode="delete")
                    await asyncio.wait_for(
                        runner._active_task,
                        timeout=5,
                    )

                record = runner.get(created.run_id)
                observe_mock.assert_called_once()

            self.assertEqual(
                order,
                ["cleanup", "events", "observation"],
            )
            self.assertEqual(record.status, status)
            self.assertEqual(record.result, payload)
            self.assertIsNotNone(record.finished_at)
            self.assertIsNone(record.protection_verification)

            return record
        finally:
            await runner.close()

    async def test_completed_execution_stores_file_observation(self):
        record = await self.run_case()

        self.assertEqual(
            record.deletion_observation["status"],
            "observed",
        )

    async def test_timed_out_execution_still_observes_files(self):
        record = await self.run_case(status="timed_out")

        self.assertEqual(
            record.deletion_observation["status"],
            "observed",
        )
        self.assertEqual(record.status, "timed_out")

    async def test_observation_error_does_not_hide_execution_result(self):
        record = await self.run_case(observation_error=True)

        self.assertEqual(
            record.deletion_observation["status"],
            "unknown",
        )
        self.assertTrue(record.deletion_observation["issues"])
        self.assertEqual(record.status, "passed")


if __name__ == "__main__":
    unittest.main()
