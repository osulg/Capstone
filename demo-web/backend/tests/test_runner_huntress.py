"""Huntress 일반 읽기의 runner 연결과 최종 결과 검증."""

import asyncio
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

from app.schemas.run import RunEventCollection, RunProcess
from app.services.runner import ScenarioRunner, now

from scenarios.catalog import get_scenario
from scenarios.huntress_config import READ_FILES

TASK_DEFINITIONS = (
    ("huntress_prepare", "prepare", "PREPARE"),
    ("huntress_verify_ready", "verify", "VERIFY_READY"),
    ("huntress_read", "read", "READ"),
    ("huntress_verify_mount", "verify", "VERIFY_MOUNT"),
    ("huntress_verify_underlay", "verify", "VERIFY_UNDERLAY"),
)


class HuntressRunnerTests(unittest.IsolatedAsyncioTestCase):
    def make_result(self, status="passed"):
        """관리자가 반환하는 형식의 최종 결과를 만든다."""
        failure = {
            "operation": "read",
            "path": "/runtime/mount/test/.ssh/id_rsa",
            "errno": 13 if status == "failed" else None,
            "message": (
                "읽기 제한 시간을 초과했습니다."
                if status == "timed_out"
                else "테스트용 읽기 접근 거절"
            ),
        }

        step_results = [
            {
                "name": "PRECHECK",
                "status": "passed",
                "planned": 1,
                "attempted": 1,
                "completed": 1,
                "failure": None,
            }
        ]
        task_results = []

        for index, (role, action, step_name) in enumerate(TASK_DEFINITIONS):
            failed = step_name == "READ" and status != "passed"

            step = {
                "name": step_name,
                "status": "failed" if failed else "passed",
                "planned": 1,
                "attempted": 1,
                "completed": 0 if failed else 1,
                "failure": failure.copy() if failed else None,
            }
            if failed:
                step["error"] = failure["message"]

            step_results.append(step)

            file_results = []
            for file_index, filename in enumerate(READ_FILES):
                file_failed = failed and file_index == 0

                item = {
                    "name": filename,
                    "path": f"/runtime/mount/test/{filename}",
                    "status": "failed" if file_failed else "passed",
                }

                if action in ("read", "verify"):
                    item["content_matched"] = True

                file_results.append(item)

            task_results.append(
                {
                    "role": role,
                    "pid": 200 + index,
                    "action": action,
                    "status": status if failed else "passed",
                    "planned": 6,
                    "attempted": 6,
                    "completed": 5 if failed else 6,
                    "failure": failure.copy() if failed else None,
                    "operations": file_results,
                }
            )

            # 실패한 읽기 뒤의 내용 검증은 실행하지 않는다.
            if failed:
                break

        return {
            "result_version": 2,
            "scenario_id": "S03",
            "mode": "read",
            "pid": 123,
            "holdfs_pid": 999,
            "status": status,
            "termination_reason": {
                "passed": "completed",
                "failed": "operation_failed",
                "timed_out": "deadline_exceeded",
            }[status],
            "steps": step_results,
            "task_results": task_results,
            "content_verification": (
                {
                    "status": "passed",
                    "files": 6,
                    "observed_at": now().isoformat(),
                }
                if status == "passed"
                else {"status": "not_checked"}
            ),
            "detection_verification": "not_checked",
        }

    async def run_result(
        self,
        result,
        *,
        invalid_result=False,
        missing_role=None,
    ):
        """실제 runner를 실행하고 외부 프로세스만 대체한다."""
        scenario = get_scenario("S03")
        self.assertIsNotNone(scenario)
        self.assertTrue(scenario.enabled)
        self.assertEqual(
            scenario.module,
            "scenarios.s03_huntress",
        )

        runner = ScenarioRunner()
        process = SimpleNamespace(
            pid=123,
            returncode=0 if result["status"] == "passed" else 1,
        )

        operation_order = []
        applied_timeouts = []
        original_wait = asyncio.wait

        async def collect_output(child_process, record, definition):
            # 실제 실행에서는 등록 이벤트를 받아 채워지는 정보다.
            for index, (role, _, _) in enumerate(TASK_DEFINITIONS):
                if role == missing_role:
                    continue

                record.processes.append(
                    RunProcess(
                        role=role,
                        pid=200 + index,
                        start_time_ticks=1000 + index,
                        registered_at=now(),
                    )
                )

            return json.dumps(result).encode("utf-8")

        async def cleanup_process(*args):
            operation_order.append("프로세스 정리")

        def collect_events(*args):
            operation_order.append("이벤트 수집")
            return RunEventCollection(issues=[])

        async def check_timeout(tasks, **options):
            applied_timeouts.append(options.get("timeout"))
            return await original_wait(tasks, **options)

        try:
            with (
                patch.object(
                    runner,
                    "_capture_event_logs",
                    return_value=([], []),
                ),
                patch(
                    "app.services.runner.asyncio.create_subprocess_exec",
                    new=AsyncMock(return_value=process),
                ) as spawn,
                patch.object(
                    runner,
                    "_collect_output",
                    new=AsyncMock(side_effect=collect_output),
                ),
                patch.object(
                    runner,
                    "_terminate_process_group",
                    new=AsyncMock(side_effect=cleanup_process),
                ) as cleanup_mock,
                patch.object(
                    runner,
                    "_collect_run_events",
                    side_effect=collect_events,
                ) as events_mock,
                patch(
                    "app.services.runner.asyncio.wait",
                    side_effect=check_timeout,
                ),
            ):
                if invalid_result:
                    with self.assertLogs(
                        "app.services.runner",
                        level="ERROR",
                    ):
                        created = runner.start(
                            "S03",
                            mode="read",
                        )
                        await asyncio.wait_for(
                            runner._active_task,
                            timeout=5,
                        )
                else:
                    created = runner.start(
                        "S03",
                        mode="read",
                    )
                    await asyncio.wait_for(
                        runner._active_task,
                        timeout=5,
                    )

                record = runner.get(created.run_id)
                command = spawn.call_args.args

                self.assertEqual(created.mode, "read")
                self.assertEqual(record.mode, "read")

                self.assertEqual(
                    command[command.index("-m") + 1],
                    "scenarios.s03_huntress",
                )
                self.assertEqual(command.count("--mode"), 1)
                self.assertEqual(
                    command[command.index("--mode") + 1],
                    "read",
                )
                self.assertEqual(
                    command[command.index("--work-dir-name") + 1],
                    record.workspace.name,
                )
                self.assertEqual(
                    record.workspace.name,
                    f"s03_{created.run_id}",
                )
                self.assertEqual(
                    float(command[command.index("--total-timeout") + 1]),
                    120.0,
                )
                self.assertEqual(applied_timeouts, [120.0])

                cleanup_mock.assert_awaited_once_with(process)
                events_mock.assert_called_once()

            self.assertEqual(
                operation_order,
                ["프로세스 정리", "이벤트 수집"],
            )
            self.assertIsNotNone(record.finished_at)
            self.assertEqual(
                record.detection_verification,
                "not_checked",
            )

            return record
        finally:
            await runner.close()

    async def test_read_completes_all_steps(self):
        result = self.make_result()
        record = await self.run_result(result)

        self.assertEqual(record.status, "passed")
        self.assertEqual(record.result, result)
        self.assertTrue(all(step.status == "passed" for step in record.steps))

        # 읽기 완료를 공격 차단 성공으로 판정하지 않는다.
        self.assertIsNone(record.protection_verification)
        self.assertEqual(
            record.result["content_verification"]["status"],
            "passed",
        )

    async def test_read_failure_and_timeout_preserve_partial_results(self):
        for status in ("failed", "timed_out"):
            with self.subTest(status=status):
                result = self.make_result(status)
                record = await self.run_result(result)

                self.assertEqual(record.status, status)
                self.assertEqual(record.result, result)
                self.assertEqual(
                    record.result["task_results"][-1]["completed"],
                    5,
                )
                self.assertEqual(
                    record.steps[-1].status,
                    "skipped",
                )

    async def test_mismatched_mode_is_rejected(self):
        result = self.make_result()
        result["mode"] = "honeypot"

        record = await self.run_result(
            result,
            invalid_result=True,
        )

        self.assertEqual(record.status, "failed")
        self.assertIsNone(record.result)
        self.assertIn("실행 모드", record.error)

    async def test_unregistered_child_result_is_rejected(self):
        result = self.make_result()

        record = await self.run_result(
            result,
            invalid_result=True,
            missing_role="huntress_read",
        )

        self.assertEqual(record.status, "failed")
        self.assertIsNone(record.result)
        self.assertIn("등록되지 않은", record.error)

    async def test_success_without_content_verification_is_rejected(self):
        result = self.make_result()
        result["content_verification"] = {
            "status": "not_checked",
        }

        record = await self.run_result(
            result,
            invalid_result=True,
        )

        self.assertEqual(record.status, "failed")
        self.assertIsNone(record.result)
        self.assertIn("내용 불변", record.error)

    async def test_success_with_incomplete_count_is_rejected(self):
        result = self.make_result()
        result["task_results"][2]["completed"] = 5

        record = await self.run_result(
            result,
            invalid_result=True,
        )

        self.assertEqual(record.status, "failed")
        self.assertIsNone(record.result)


if __name__ == "__main__":
    unittest.main()
