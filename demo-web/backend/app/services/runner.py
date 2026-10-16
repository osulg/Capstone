"""
backend/app/services/runner.py

- 단일 서버 프로세스에서 S01 실행 및 결과 관리
"""

import asyncio
import json
import logging
import math
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from guardfs.common.paths import PROJECT_ROOT as HOLDFS_PROJECT_ROOT
from scenarios.catalog import Scenario, get_scenario

from ..schemas.run import RunCreatedResponse, RunResponse, RunStepResponse

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(HOLDFS_PROJECT_ROOT)


def now() -> datetime:
    return datetime.now(UTC)


class RunBusyError(RuntimeError):
    """다른 테스트가 실행 중"""


class ScenarioUnavailableError(ValueError):
    """등록되지 않았거나 실행할 수 없는 시나리오"""


class ScenarioRunner:
    def __init__(
        self,
        timeout_seconds: float = 150,
        cleanup_seconds: float = 5,
    ):
        if not all(
            math.isfinite(value) and value > 0
            for value in (timeout_seconds, cleanup_seconds)
        ):
            raise ValueError("실행 및 종료 대기 시간은 양수여야 합니다.")

        self.timeout_seconds = timeout_seconds
        self.cleanup_seconds = cleanup_seconds

        self._runs: dict[str, RunResponse] = {}
        self._active_task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._cleanup_blocked = False
        self._pending_cleanup: set[asyncio.Task] = set()
        self._closed = False

    def start(self, scenario_id: str) -> RunCreatedResponse:
        """실행을 예약하고 실행 ID를 즉시 반환"""
        if self._closed:
            raise RuntimeError("실행 관리자가 종료되었습니다.")

        scenario = get_scenario(scenario_id)

        if scenario is None:
            raise ScenarioUnavailableError("등록되지 않은 시나리오입니다.")

        if not scenario.enabled or not scenario.module:
            raise ScenarioUnavailableError(
                scenario.disabled_reason or "실행할 수 없는 시나리오입니다."
            )

        # 현재 구현은 자식 프로세스를 만들지 않는 S01만 지원
        if scenario.module != "scenarios.s01_normal":
            raise ScenarioUnavailableError("현재 실행 관리자는 S01만 지원합니다.")

        if self._cleanup_blocked:
            raise RunBusyError(
                "이전 테스트의 종료를 확인하지 못했습니다. HoldFS와 PID를 점검하세요."
            )

        if self._active_task and not self._active_task.done():
            raise RunBusyError("다른 테스트가 실행 중입니다.")

        # API의 async 핸들러에서 호출해야 한다. 실패한 예약 기록은 남기지 않는다.
        loop = asyncio.get_running_loop()
        run_id = uuid.uuid4().hex

        record = RunResponse(
            run_id=run_id,
            scenario_id=scenario.id,
            status="queued",
            created_at=now(),
            steps=[
                RunStepResponse(id=step.id, name=step.name) for step in scenario.steps
            ],
        )
        self._runs[run_id] = record

        self._active_task = loop.create_task(
            self._execute(record, scenario),
            name=f"scenario-{run_id}",
        )

        return RunCreatedResponse(
            run_id=run_id,
            scenario_id=scenario.id,
            status="queued",
        )

    def get(self, run_id: str) -> RunResponse:
        """조회자가 내부 실행 기록을 변경하지 못하도록 복사한다."""
        if run_id not in self._runs:
            raise KeyError(run_id)

        return self._runs[run_id].model_copy(deep=True)

    async def close(self):
        """서버 종료 시 실행 중인 테스트도 종료한다."""
        self._closed = True
        self._stop.set()

        if self._active_task and not self._active_task.done():
            # 생성 중인 프로세스를 놓치지 않도록 작업 자체는 취소하지 않는다.
            await asyncio.shield(self._active_task)

    async def _execute(
        self,
        record: RunResponse,
        scenario: Scenario,
    ):
        process = None
        communication = None
        stop_wait = None

        record.status = "running"
        record.started_at = now()

        try:
            if self._stop.is_set():
                record.status = "failed"
                record.error = "서버 종료로 실행을 취소했습니다."
                return

            process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-u",
                "-m",
                scenario.module,
                cwd=str(PROJECT_ROOT),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            record.pid = process.pid

            # stdout·stderr를 함께 읽어 파이프가 차는 것을 방지한다.
            communication = asyncio.create_task(process.communicate())

            stop_wait = asyncio.create_task(self._stop.wait())
            done, _ = await asyncio.wait(
                {communication, stop_wait},
                timeout=self.timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )

            if communication not in done:
                if stop_wait in done:
                    record.status = "failed"
                    record.error = "서버 종료로 테스트를 중단했습니다."
                    return
                raise TimeoutError

            stdout, stderr = communication.result()

            stderr_text = stderr.decode("utf-8", errors="replace")

            if stderr_text:
                logger.info(
                    "Scenario run %s stderr:\n%s",
                    record.run_id,
                    stderr_text,
                )

            result = json.loads(stdout.decode("utf-8"))

            self._validate_result(result, record, scenario)

            record.result = result
            # 기존 S01 출력 키를 지원하면서 API 명칭은 HoldFS로 통일한다.
            record.holdfs_pid = result.get("holdfs_pid", result.get("guardfs_pid"))

            self._map_steps(record, scenario, result)

            all_steps_passed = all(step.status == "passed" for step in record.steps)

            if (
                process.returncode == 0
                and result["status"] == "passed"
                and all_steps_passed
            ):
                record.status = "passed"
            else:
                record.status = "failed"
                record.error = next(
                    (step.error for step in record.steps if step.error),
                    f"테스트 실패: 종료 코드 {process.returncode}",
                )

            # 파일 작업 성공과 탐지 검증은 구분한다.
            record.detection_verification = "not_checked"

        except TimeoutError:
            record.status = "timed_out"
            record.error = f"실행 제한 시간 {self.timeout_seconds}초를 초과했습니다."

        except asyncio.CancelledError:
            record.status = "failed"
            record.error = "서버 종료로 테스트를 중단했습니다."
            raise

        except Exception as error:
            # 백그라운드 예외를 실행 결과와 서버 로그에 모두 남긴다.
            logger.exception("Scenario run failed: %s", record.run_id)
            record.status = "failed"
            record.error = f"{type(error).__name__}: {error}"

        finally:
            try:
                if stop_wait is not None:
                    stop_wait.cancel()
                    await asyncio.gather(stop_wait, return_exceptions=True)
                if process and process.returncode is None:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass

                cleanup = communication
                if cleanup is None and process is not None:
                    cleanup = asyncio.create_task(process.wait())
                if cleanup is not None:
                    try:
                        await asyncio.wait_for(
                            asyncio.shield(cleanup), timeout=self.cleanup_seconds
                        )
                    except TimeoutError:
                        self._cleanup_blocked = True
                        record.error = (record.error or "종료 처리 실패") + (
                            " 종료를 확인하지 못해 새 실행을 차단했습니다."
                        )
                        self._pending_cleanup.add(cleanup)
                        cleanup.add_done_callback(self._cleanup_done)
                    except Exception:
                        self._cleanup_blocked = True
                        logger.exception("테스트 종료 확인 실패: %s", record.run_id)
                        record.status = "failed"
                        record.error = "테스트 종료 확인 실패로 새 실행을 차단했습니다."
            except OSError as error:
                # kill() 실패도 기록하고, 실행 태스크 밖으로 유실시키지 않는다.
                self._cleanup_blocked = True
                record.status = "failed"
                record.error = f"테스트 종료 요청 실패: {error}"
                logger.exception("테스트 종료 요청 실패: %s", record.run_id)
                if communication is not None:
                    self._pending_cleanup.add(communication)
                    communication.add_done_callback(self._cleanup_done)
            finally:
                for step in record.steps:
                    if step.status == "pending":
                        step.status = "skipped"

                record.finished_at = now()

    def _cleanup_done(self, task):
        self._pending_cleanup.discard(task)
        if not task.cancelled():
            # 늦게 끝난 작업의 예외도 회수한다. 차단 해제는 자동으로 하지 않는다.
            error = task.exception()
            if error is not None:
                logger.error("지연 종료 처리 실패: %s", error)

    @staticmethod
    def _validate_result(
        result: dict,
        record: RunResponse,
        scenario: Scenario,
    ):
        if not isinstance(result, dict):
            raise ValueError("테스트 결과가 JSON 객체가 아닙니다.")

        if result.get("scenario_id") != scenario.id:
            raise ValueError("시나리오 ID가 일치하지 않습니다.")

        if result.get("pid") != record.pid:
            raise ValueError("테스트 PID가 일치하지 않습니다.")

        if result.get("status") not in ("passed", "failed"):
            raise ValueError("잘못된 테스트 상태입니다.")

        operations = result.get("steps")

        if not isinstance(operations, list):
            raise ValueError("단계별 결과가 없습니다.")

        names = []

        for operation in operations:
            if not isinstance(operation, dict):
                raise ValueError("잘못된 단계 결과입니다.")

            name = operation.get("name")

            if not isinstance(name, str):
                raise ValueError("단계 이름이 없습니다.")

            if operation.get("status") not in ("passed", "failed"):
                raise ValueError("잘못된 단계 상태입니다.")

            names.append(name)

        if len(names) != len(set(names)):
            raise ValueError("중복된 단계 결과입니다.")

        expected = [name for step in scenario.steps for name in step.operation_names]
        # 현재 S01은 첫 실패에서 중단하므로 결과는 실행 순서의 앞부분이어야 한다.
        if not names or names != expected[: len(names)]:
            raise ValueError("단계 결과가 등록된 실행 순서와 일치하지 않습니다.")

        statuses = [operation["status"] for operation in operations]
        if result["status"] == "passed":
            if names != expected or any(status != "passed" for status in statuses):
                raise ValueError("성공 결과에 누락되거나 실패한 단계가 있습니다.")
        elif statuses[-1] != "failed" or "failed" in statuses[:-1]:
            raise ValueError("실패 결과의 단계 상태가 일치하지 않습니다.")

    @staticmethod
    def _map_steps(
        record: RunResponse,
        scenario: Scenario,
        result: dict,
    ):
        operations = {operation["name"]: operation for operation in result["steps"]}

        for definition, step in zip(scenario.steps, record.steps):
            matched = [
                operations[name]
                for name in definition.operation_names
                if name in operations
            ]

            failed = next(
                (operation for operation in matched if operation["status"] == "failed"),
                None,
            )

            if failed:
                step.status = "failed"
                step.error = failed.get("error") or f"{failed['name']} 단계 실패"
            elif (
                definition.operation_names
                and len(matched) == len(definition.operation_names)
                and all(operation["status"] == "passed" for operation in matched)
            ):
                step.status = "passed"
            else:
                step.status = "skipped"
