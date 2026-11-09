"""runner의 허니팟 보호 검증 연결 검사."""

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


class RunnerHoneypotVerificationTests(unittest.IsolatedAsyncioTestCase):
    async def run_case(self, *, mode="honeypot", verdict=None, error=None):
        original = get_scenario("S02")

        # 실제 카탈로그는 변경하지 않고 테스트에서만 허니팟을 허용한다.
        scenario = replace(
            original,
            modes=tuple(
                replace(item, enabled=True, disabled_reason=None)
                if item.id == mode
                else item
                for item in original.modes
            ),
        )

        runner = ScenarioRunner()
        process = SimpleNamespace(pid=123, returncode=0)
        order = []
        snapshots = []

        payload = {
            "scenario_id": "S02",
            "mode": mode,
            "pid": process.pid,
            "status": "passed",
        }

        if verdict is None:
            verdict = {
                "status": "passed",
                "reason": "테스트 차단 근거 확인",
                "blocking_events": [],
            }

        async def collect_output(*args):
            return json.dumps(payload).encode("utf-8")

        async def cleanup_process(*args):
            order.append("cleanup")

        def collect_events(*args):
            order.append("events")
            return RunEventCollection(
                captured_sources=["filesystem"],
                issues=[],
            )

        def map_steps(record, definition, result):
            # 단계 매핑 자체는 기존 테스트에서 검사한다.
            for step in record.steps:
                step.status = "passed"

        def verify(record, *, cleanup_confirmed):
            order.append("verification")
            snapshots.append(record)

            self.assertTrue(cleanup_confirmed)
            self.assertIsNotNone(record.event_collection)
            self.assertEqual(
                record.event_collection.captured_sources,
                ["filesystem"],
            )

            if error is not None:
                raise error

            return verdict

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
                    "app.services.runner.verify_honeypot_protection",
                    side_effect=verify,
                ) as verify_mock,
            ):
                if error is not None:
                    with self.assertLogs(
                        "app.services.runner",
                        level="ERROR",
                    ):
                        created = runner.start("S02", mode=mode)
                        await asyncio.wait_for(
                            runner._active_task,
                            timeout=5,
                        )
                else:
                    created = runner.start("S02", mode=mode)
                    await asyncio.wait_for(
                        runner._active_task,
                        timeout=5,
                    )

                record = runner.get(created.run_id)

                if mode == "honeypot":
                    verify_mock.assert_called_once()
                else:
                    verify_mock.assert_not_called()

            # 최종 정리가 끝나면 완료 시각과 실행 결과가 공개되어야 한다.
            self.assertIsNotNone(record.finished_at)
            self.assertEqual(record.status, "passed")
            self.assertEqual(record.result, payload)
            self.assertEqual(record.detection_verification, "not_checked")
            self.assertTrue(all(step.status == "passed" for step in record.steps))

            return record, order, snapshots
        finally:
            await runner.close()

    async def test_verification_follows_cleanup_and_event_collection(self):
        record, order, snapshots = await self.run_case()

        self.assertEqual(
            order,
            ["cleanup", "events", "verification"],
        )
        self.assertEqual(
            record.protection_verification["status"],
            "passed",
        )

        # 완료 시각은 보호 검증까지 끝난 후 기록한다.
        self.assertIsNone(snapshots[0].finished_at)

    async def test_protection_verdict_does_not_replace_execution_status(self):
        for status in ("failed", "unknown"):
            with self.subTest(status=status):
                verdict = {
                    "status": status,
                    "reason": "테스트 보호 검증 결과",
                    "blocking_events": [],
                }

                record, _, _ = await self.run_case(verdict=verdict)

                self.assertEqual(
                    record.protection_verification["status"],
                    status,
                )
                self.assertEqual(record.status, "passed")

    async def test_verification_error_is_recorded_as_unknown(self):
        record, order, _ = await self.run_case(
            error=RuntimeError("test verification error"),
        )

        self.assertEqual(
            order,
            ["cleanup", "events", "verification"],
        )
        self.assertEqual(
            record.protection_verification["status"],
            "unknown",
        )
        self.assertIn(
            "RuntimeError",
            record.protection_verification["reason"],
        )

    async def test_read_mode_does_not_call_honeypot_verification(self):
        record, order, _ = await self.run_case(mode="read")

        self.assertEqual(order, ["cleanup", "events"])
        self.assertIsNone(record.protection_verification)


if __name__ == "__main__":
    unittest.main()
