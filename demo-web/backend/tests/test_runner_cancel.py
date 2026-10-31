"""사용자 중단 상태와 재실행 가능 여부를 검사한다."""

import asyncio
import sys
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parents[1]

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(BACKEND))

from app.api.runs import cancel_run
from app.schemas.run import RunResponse
from app.services.runner import RunBusyError, ScenarioRunner, now


@asynccontextmanager
async def running_runner(*, cleanup_failure=False):
    """실제 프로세스를 만들지 않는 실행 환경."""

    runner = ScenarioRunner(
        timeout_seconds=10,
        cleanup_seconds=1,
    )
    ready = asyncio.Event()
    released = asyncio.Event()

    process = SimpleNamespace(pid=12345, returncode=None)

    async def collect_output(*args):
        ready.set()
        await released.wait()
        return b""

    async def terminate_group(target):
        target.returncode = -15
        released.set()

        if cleanup_failure:
            # 관리자는 끝났지만 그룹 정리는 확인하지 못한 상황.
            raise TimeoutError("group still exists")

    with (
        patch(
            "app.services.runner.asyncio.create_subprocess_exec",
            new=AsyncMock(return_value=process),
        ),
        patch.object(
            runner,
            "_collect_output",
            side_effect=collect_output,
        ),
        patch.object(
            runner,
            "_terminate_process_group",
            side_effect=terminate_group,
        ) as terminate,
    ):
        try:
            yield runner, ready, released, process, terminate
        finally:
            # 테스트 실패 시에도 대기 태스크가 남지 않도록 정리한다.
            released.set()
            await runner.close()


class RunnerCancelTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancel_before_process_creation(self):
        runner = ScenarioRunner()

        with patch(
            "app.services.runner.asyncio.create_subprocess_exec",
            new=AsyncMock(),
        ) as spawn:
            # await 전에 요청하므로 실행 태스크가 아직 시작되지 않았다.
            created = runner.start("S01")
            response = runner.cancel(created.run_id)

            self.assertEqual(response.status, "cancelling")

            await asyncio.wait_for(runner._active_task, timeout=3)

            result = runner.get(created.run_id)
            self.assertEqual(result.status, "cancelled")
            self.assertIsNone(result.pid)
            self.assertIsNotNone(result.finished_at)
            spawn.assert_not_awaited()

        await runner.close()

    async def test_cancel_running_execution(self):
        async with running_runner() as (runner, ready, _, process, terminate):
            created = runner.start("S01")
            await asyncio.wait_for(ready.wait(), timeout=3)

            response = runner.cancel(created.run_id)
            self.assertEqual(response.status, "cancelling")

            await asyncio.wait_for(runner._active_task, timeout=3)

            result = runner.get(created.run_id)
            self.assertEqual(result.status, "cancelled")
            self.assertIsNotNone(result.finished_at)
            self.assertFalse(runner._cleanup_blocked)
            terminate.assert_awaited_once_with(process)

    async def test_repeated_cancel_is_idempotent(self):
        async with running_runner() as (runner, ready, _, process, terminate):
            created = runner.start("S01")
            await asyncio.wait_for(ready.wait(), timeout=3)

            runner.cancel(created.run_id)
            response = runner.cancel(created.run_id)
            self.assertEqual(response.status, "cancelling")

            await asyncio.wait_for(runner._active_task, timeout=3)

            response = runner.cancel(created.run_id)
            self.assertEqual(response.status, "cancelled")
            terminate.assert_awaited_once_with(process)

    async def test_completed_result_is_preserved(self):
        runner = ScenarioRunner()

        record = RunResponse(
            run_id="finished-run",
            scenario_id="S01",
            status="passed",
            created_at=now(),
            finished_at=now(),
        )
        runner._runs[record.run_id] = record

        response = runner.cancel(record.run_id)

        self.assertEqual(response.status, "passed")
        self.assertEqual(response.finished_at, record.finished_at)
        await runner.close()

    async def test_unknown_run_returns_404(self):
        runner = ScenarioRunner()
        request = SimpleNamespace(
            app=SimpleNamespace(
                state=SimpleNamespace(runner=runner),
            ),
        )

        with self.assertRaises(HTTPException) as raised:
            await cancel_run("missing-run", request)

        self.assertEqual(raised.exception.status_code, 404)
        await runner.close()

    async def test_cleanup_failure_does_not_report_cancelled(self):
        async with running_runner(cleanup_failure=True) as (runner, ready, _, _, _):
            created = runner.start("S01")
            await asyncio.wait_for(ready.wait(), timeout=3)

            with self.assertLogs(
                "app.services.runner",
                level="ERROR",
            ):
                runner.cancel(created.run_id)
                await asyncio.wait_for(
                    runner._active_task,
                    timeout=3,
                )

            result = runner.get(created.run_id)
            self.assertEqual(result.status, "failed")
            self.assertTrue(runner._cleanup_blocked)

            with self.assertRaises(RunBusyError):
                runner.start("S01")

    async def test_new_execution_has_independent_cancel_event(self):
        async with running_runner() as (runner, ready, released, process, _):
            first = runner.start("S01")
            await asyncio.wait_for(ready.wait(), timeout=3)

            runner.cancel(first.run_id)
            await asyncio.wait_for(runner._active_task, timeout=3)

            ready.clear()
            released.clear()
            process.returncode = None

            second = runner.start("S01")
            await asyncio.wait_for(ready.wait(), timeout=3)

            self.assertNotEqual(first.run_id, second.run_id)
            self.assertEqual(
                runner.get(second.run_id).status,
                "running",
            )
            self.assertFalse(
                runner._cancel_events[second.run_id].is_set(),
            )

            # 두 번째 실행도 테스트 종료 전에 정리한다.
            runner.cancel(second.run_id)
            await asyncio.wait_for(runner._active_task, timeout=3)

    async def test_output_cleanup_timeout_is_terminal_failure(self):
        """종료 확인 실패 시 중단 진행 상태에 머물지 않는지 확인한다."""
        runner = ScenarioRunner(timeout_seconds=5, cleanup_seconds=0.02)
        ready = asyncio.Event()
        released = asyncio.Event()
        process = SimpleNamespace(pid=12345, returncode=None)

        async def collect_output(*args):
            ready.set()
            await released.wait()
            return b""

        async def terminate_group(target):
            target.returncode = -15
            # 관리자는 끝났지만 출력 수집은 완료되지 않은 상황을 재현한다.

        with (
            patch(
                "app.services.runner.asyncio.create_subprocess_exec",
                new=AsyncMock(return_value=process),
            ),
            patch.object(runner, "_collect_output", side_effect=collect_output),
            patch.object(
                runner, "_terminate_process_group", side_effect=terminate_group,
            ),
        ):
            try:
                created = runner.start("S01")
                await asyncio.wait_for(ready.wait(), timeout=3)
                runner.cancel(created.run_id)
                await asyncio.wait_for(runner._active_task, timeout=3)

                result = runner.get(created.run_id)
                self.assertEqual(result.status, "failed")
                self.assertIsNotNone(result.finished_at)
                self.assertTrue(runner._cleanup_blocked)
            finally:
                released.set()
                if runner._pending_cleanup:
                    await asyncio.wait_for(
                        asyncio.gather(*tuple(runner._pending_cleanup)), timeout=3,
                    )
                await runner.close()


if __name__ == "__main__":
    unittest.main()
