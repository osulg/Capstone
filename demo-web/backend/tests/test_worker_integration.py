"""실제 자식 프로세스와 runner의 등록 응답 연결을 검증한다."""

import asyncio
import json
import os
import signal
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

# 프로젝트 루트와 백엔드 경로를 import 경로에 등록한다.
BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parents[1]

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(BACKEND))

from app.schemas.run import RunResponse
from app.services.runner import ScenarioRunner, now
from scenario_fixtures import NormalScenarioMixin, get_test_scenario as get_scenario

# 별도 프로세스에서 실행할 검증용 관리자 코드.
# S01 파일 작업을 실행하는 것이 아니라 등록 프로토콜만 이용한다.
MANAGER_CODE = """
import json
import sys

from scenarios.workers import registered_worker

with registered_worker(
    "S01",
    "test_worker",
    [sys.executable, "-c", "raise SystemExit(23)"],
) as (process, metadata):
    return_code = process.wait(timeout=5)

    print(
        json.dumps({
            "worker_pid": process.pid,
            "registered_pid": metadata["pid"],
            "return_code": return_code,
        }),
        flush=True,
    )
"""


FAILURE_MANAGER_CODE = """
import json
import os
import subprocess
import sys
from unittest.mock import patch

from scenarios import common
from scenarios.workers import registered_worker

mode = os.environ["WORKER_TEST_MODE"]
captured = {}
original_popen = subprocess.Popen
original_emit = common._emit_event


def capture_process(*args, **kwargs):
    process = original_popen(*args, **kwargs)
    captured["process"] = process
    return process


def emit_event(event):
    if mode == "reject" and event.get("type") == "process":
        # 실제 /proc 정보와 다른 시작 시각을 보내 runner가 거절하게 한다.
        event = dict(event)
        event["process"] = dict(event["process"])
        event["process"]["start_time_ticks"] += 1
    original_emit(event)


try:
    with (
        patch("scenarios.workers.subprocess.Popen", side_effect=capture_process),
        patch("scenarios.common._emit_event", side_effect=emit_event),
    ):
        with registered_worker(
            "S01",
            "test_worker",
            [
                sys.executable,
                "-c",
                "import sys; print('WORK_STARTED', file=sys.stderr, flush=True)",
            ],
        ):
            raise AssertionError("등록 실패 후 작업이 시작됐습니다.")
except RuntimeError as error:
    process = captured["process"]
    print(json.dumps({
        "error": str(error),
        "worker_pid": process.pid,
        "worker_reaped": process.returncode is not None,
    }, ensure_ascii=False), flush=True)
    raise SystemExit(1)
"""


@unittest.skipUnless(
    sys.platform == "linux",
    "실제 /proc 검증은 Linux에서 수행합니다.",
)
class WorkerIntegrationTests(NormalScenarioMixin, unittest.IsolatedAsyncioTestCase):
    async def _check_registration_failure(self, mode):
        """실제 등록 거절 또는 응답 통로 종료 시 자식 회수를 확인한다."""
        scenario = get_scenario("S01")
        self.assertIsNotNone(scenario)

        environment = os.environ.copy()
        paths = [str(ROOT), str(BACKEND)]
        if environment.get("PYTHONPATH"):
            paths.append(environment["PYTHONPATH"])
        environment["PYTHONPATH"] = os.pathsep.join(paths)
        environment["WORKER_TEST_MODE"] = mode

        manager = await asyncio.create_subprocess_exec(
            sys.executable,
            "-u",
            "-c",
            FAILURE_MANAGER_CODE,
            cwd=str(ROOT),
            env=environment,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        record = RunResponse(
            run_id=f"worker-{mode}-test",
            scenario_id="S01",
            status="running",
            pid=manager.pid,
            created_at=now(),
        )
        runner = ScenarioRunner()
        stderr_lines = []

        class RecordingReader:
            async def readline(self):
                line = await manager.stderr.readline()
                stderr_lines.append(line)
                return line

        progress_process = SimpleNamespace(
            pid=manager.pid,
            stdin=manager.stdin,
            stderr=RecordingReader(),
        )

        async def handle_registration():
            if mode == "reject":
                await runner._read_progress(progress_process, record, scenario)
                return

            # 등록 요청을 받은 뒤 응답 없이 stdin을 닫아 EOF를 전달한다.
            line = await manager.stderr.readline()
            stderr_lines.append(line)
            self.assertTrue(line.startswith(b"PROGRESS "))
            event = json.loads(line[len(b"PROGRESS ") :])
            self.assertEqual(event["type"], "process")
            manager.stdin.close()
            await manager.stdin.wait_closed()
            stderr_lines.append(await manager.stderr.read())

        tasks = [
            asyncio.create_task(handle_registration()),
            asyncio.create_task(manager.stdout.read()),
            asyncio.create_task(manager.wait()),
        ]
        try:
            protocol_result, output, return_code = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=15,
            )
            if mode == "reject":
                self.assertIsInstance(protocol_result, ValueError)
            elif isinstance(protocol_result, BaseException):
                raise protocol_result
            if isinstance(output, BaseException):
                raise output
            if isinstance(return_code, BaseException):
                raise return_code

            self.assertEqual(return_code, 1)
            result = json.loads(output.decode("utf-8"))
            expected_error = "등록 거절" if mode == "reject" else "통로가 종료"
            self.assertIn(expected_error, result["error"])
            self.assertEqual(record.processes, [])

            # 테스트의 강제 정리 전에 공통 함수가 이미 자식을 회수해야 한다.
            self.assertTrue(result["worker_reaped"])
            self.assertNotIn(b"WORK_STARTED", b"".join(stderr_lines))
        finally:
            # 테스트가 생성한 독립 그룹만 정리한다.
            try:
                os.killpg(manager.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await manager.wait()
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if manager.stdin is not None:
                manager.stdin.close()
            await runner.close()

    async def test_registration_rejection_reaps_child(self):
        await self._check_registration_failure("reject")

    async def test_response_channel_closed_reaps_child(self):
        await self._check_registration_failure("closed")

    async def test_child_registration_and_start(self):
        scenario = get_scenario("S01")
        self.assertIsNotNone(scenario)

        environment = os.environ.copy()

        # 관리자와 자식이 프로젝트 모듈을 찾을 수 있도록 설정한다.
        paths = [str(ROOT), str(BACKEND)]
        if environment.get("PYTHONPATH"):
            paths.append(environment["PYTHONPATH"])

        environment["PYTHONPATH"] = os.pathsep.join(paths)

        manager = await asyncio.create_subprocess_exec(
            sys.executable,
            "-u",
            "-c",
            MANAGER_CODE,
            cwd=str(ROOT),
            env=environment,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            # 테스트가 만든 프로세스만 정리할 수 있게 독립 그룹을 생성한다.
            start_new_session=True,
        )

        record = RunResponse(
            run_id="worker-integration-test",
            scenario_id="S01",
            status="running",
            pid=manager.pid,
            created_at=now(),
        )

        runner = ScenarioRunner()

        # 실제 runner 코드가 등록 요청을 읽고 검증·응답한다.
        progress_task = asyncio.create_task(
            runner._read_progress(manager, record, scenario)
        )
        output_task = asyncio.create_task(manager.stdout.read())
        wait_task = asyncio.create_task(manager.wait())

        tasks = [progress_task, output_task, wait_task]

        try:
            _, output, manager_return_code = await asyncio.wait_for(
                asyncio.gather(*tasks),
                timeout=15,
            )

            self.assertEqual(
                manager_return_code,
                0,
                output.decode("utf-8", errors="replace"),
            )

            result = json.loads(output.decode("utf-8"))

            # 자식은 관리자와 다른 PID여야 한다.
            self.assertNotEqual(result["worker_pid"], manager.pid)

            # 등록한 PID와 실제 실행한 작업 PID가 같아야 한다.
            self.assertEqual(
                result["worker_pid"],
                result["registered_pid"],
            )

            # 실제 runner 기록에도 자식 하나가 등록되어야 한다.
            self.assertEqual(len(record.processes), 1)

            worker = record.processes[0]
            self.assertEqual(worker.role, "test_worker")
            self.assertEqual(worker.pid, result["worker_pid"])
            self.assertIsNotNone(worker.start_time_ticks)

            # 자식이 START를 받은 후 지정한 프로그램을 실행했는지 확인.
            # 23은 이 테스트에서 의도적으로 지정한 종료 코드다.
            self.assertEqual(result["return_code"], 23)

        finally:
            # 테스트 실패 시에도 이 테스트가 생성한 그룹만 정리한다.
            # 실제 서비스의 그룹 종료 기능을 구현한 것은 아니다.
            try:
                os.killpg(manager.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

            await manager.wait()

            for task in tasks:
                if not task.done():
                    task.cancel()

            await asyncio.gather(*tasks, return_exceptions=True)

            if manager.stdin is not None:
                manager.stdin.close()

            await runner.close()


if __name__ == "__main__":
    unittest.main()
