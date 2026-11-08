"""실제 IceFire catalog와 runner의 실행·결과 처리 연결 검사."""

import asyncio
import importlib.util
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

from scenarios.catalog import get_scenario

HAS_PYDANTIC = importlib.util.find_spec("pydantic") is not None
if HAS_PYDANTIC:
    from app.schemas.run import RunEventCollection
    from app.services.runner import ScenarioRunner


@unittest.skipUnless(HAS_PYDANTIC, "백엔드 Pydantic 환경이 필요합니다.")
class IceFireRunnerTests(unittest.IsolatedAsyncioTestCase):
    def make_result(self, status="passed"):
        failure = {
            "operation": "write",
            "path": "/runtime/mount/test/doc_000.docx",
            "errno": 13 if status == "failed" else None,
            "message": "테스트용 공격 작업 종료",
        }
        tasks = []
        steps = []
        for action, name, planned in (
            (None, "PRECHECK", 1),
            ("prepare", "PREPARE", 11),
            ("verify", "VERIFY_READY", 11),
            ("attack", "ACTION", 32),
        ):
            failed = name == "ACTION" and status != "passed"
            step = {
                "name": name,
                "status": "failed" if failed else "passed",
                "planned": 1,
                "attempted": 1,
                "completed": 0 if failed else 1,
                "failure": failure.copy() if failed else None,
            }
            if failed:
                step["error"] = failure["message"]
            steps.append(step)
            if action:
                tasks.append(
                    {
                        "action": action,
                        "status": status if failed else "passed",
                        "planned": planned,
                        "attempted": 2 if failed else planned,
                        "completed": 1 if failed else planned,
                        "failure": failure.copy() if failed else None,
                    }
                )
        return {
            "result_version": 2,
            "scenario_id": "S01",
            "pid": 123,
            "status": status,
            "execution_scope": "full",
            "attack_started": True,
            "termination_reason": {
                "passed": "completed",
                "failed": "operation_failed",
                "timed_out": "deadline_exceeded",
            }[status],
            "steps": steps,
            "task_results": tasks,
        }

    async def run_payload(self, payload, *, invalid=False, protected=False):
        # 실제 catalog는 유지하고 이 테스트의 runner 조회만 활성화한다.
        scenario = replace(get_scenario("S01"), enabled=True, disabled_reason=None)
        self.assertEqual(scenario.module, "scenarios.s01_icefire")
        process = SimpleNamespace(
            pid=123, returncode=0 if payload["status"] == "passed" else 1
        )
        runner = ScenarioRunner()
        order = []

        async def cleanup(*args):
            order.append("cleanup")

        def collect(*args):
            order.append("collect")
            return RunEventCollection()

        try:
            with (
                patch("app.services.runner.get_scenario", return_value=scenario),
                patch.object(runner, "_capture_event_logs", return_value=([], [])),
                patch(
                    "app.services.runner.asyncio.create_subprocess_exec",
                    new=AsyncMock(return_value=process),
                ) as spawn,
                patch.object(
                    runner,
                    "_collect_output",
                    new=AsyncMock(return_value=json.dumps(payload).encode()),
                ),
                patch.object(
                    runner,
                    "_terminate_process_group",
                    new=AsyncMock(side_effect=cleanup),
                ),
                patch.object(runner, "_collect_run_events", side_effect=collect),
                patch(
                    "app.services.runner.verify_protection",
                    return_value={
                        "status": "passed" if protected else "unknown",
                        "reason": "테스트용 보호 검증 결과",
                    },
                ),
            ):
                if invalid:
                    with self.assertLogs("app.services.runner", level="ERROR"):
                        created = runner.start("S01")
                        await asyncio.wait_for(runner._active_task, timeout=5)
                else:
                    created = runner.start("S01")
                    await asyncio.wait_for(runner._active_task, timeout=5)
                record = runner.get(created.run_id)
                command = spawn.call_args.args
                self.assertEqual(command[command.index("-m") + 1], scenario.module)
                self.assertEqual(command.count("--run-attack"), 1)
                self.assertEqual(
                    command[command.index("--work-dir-name") + 1], record.workspace.name
                )
            self.assertEqual(order, ["cleanup", "collect"])
            self.assertIsNotNone(record.finished_at)
            self.assertEqual(record.detection_verification, "not_checked")
            return record
        finally:
            await runner.close()

    async def test_full_success_maps_all_catalog_steps(self):
        payload = self.make_result()
        record = await self.run_payload(payload)
        self.assertEqual(record.status, "passed")
        self.assertEqual(record.result, payload)
        self.assertTrue(all(step.status == "passed" for step in record.steps[:-1]))
        self.assertEqual(record.steps[-1].status, "skipped")

    async def test_failed_and_timed_out_results_preserve_partial_details(self):
        for status in ("failed", "timed_out"):
            with self.subTest(status=status):
                payload = self.make_result(status)
                record = await self.run_payload(payload)
                self.assertEqual(record.status, status)
                self.assertEqual(record.result, payload)
                self.assertEqual(record.steps[-1].status, "skipped")

    async def test_protection_completion_keeps_attack_timeout(self):
        payload = self.make_result("timed_out")
        record = await self.run_payload(payload, protected=True)
        self.assertEqual(record.status, "timed_out")
        self.assertEqual(record.result, payload)
        self.assertEqual(record.steps[-1].status, "passed")
        self.assertEqual(record.protection_verification["status"], "passed")

    async def test_prepare_only_result_is_rejected(self):
        payload = self.make_result()
        payload.update(execution_scope="prepare_only", attack_started=False)
        payload["steps"].pop()
        payload["task_results"].pop()
        record = await self.run_payload(payload, invalid=True)
        self.assertEqual(record.status, "failed")
        self.assertIsNone(record.result)
        self.assertIn("준비 전용", record.error)

    async def test_incomplete_attack_cannot_pass(self):
        payload = self.make_result()
        payload["task_results"][-1]["completed"] = 31
        record = await self.run_payload(payload, invalid=True)
        self.assertEqual(record.status, "failed")
        self.assertIn("완료 수", record.error)


if __name__ == "__main__":
    unittest.main()
