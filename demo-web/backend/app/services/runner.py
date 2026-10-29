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

from ..schemas.run import (
    RunCreatedResponse,
    RunProcess,
    RunResponse,
    RunStepResponse,
)

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

    async def _read_progress(
        self,
        process,
        record: RunResponse,
        scenario: Scenario,
    ):
        """단계 이벤트와 작업 프로세스 등록 이벤트를 처리한다."""
        operations = {}

        allowed_names = {
            name for step in scenario.steps for name in step.operation_names
        }

        protocol_error = None

        while True:
            line = await process.stderr.readline()

            if not line:
                break

            text = line.decode(
                "utf-8",
                errors="replace",
            ).rstrip()

            # 일반 진단 출력은 이벤트로 해석하지 않고 로그에 남긴다.
            if not text.startswith("PROGRESS "):
                logger.info(
                    "Scenario run %s stderr: %s",
                    record.run_id,
                    text,
                )
                continue

            try:
                event = json.loads(text.removeprefix("PROGRESS "))

                if not isinstance(event, dict):
                    raise ValueError("진행 이벤트가 JSON 객체가 아닙니다.")

                # 두 종류의 이벤트 모두 동일한 관리 프로세스에서
                # 출력되어야 한다.
                if event.get("scenario_id") != scenario.id:
                    raise ValueError("이벤트의 시나리오 ID가 다릅니다.")

                emitter_pid = event.get("pid")

                if type(emitter_pid) is not int or emitter_pid != record.pid:
                    raise ValueError("이벤트의 관리 PID가 다릅니다.")

                event_type = event.get("type")

                # ── 작업 프로세스 등록 ──
                if event_type == "process":
                    payload = event.get("process")
                    request_id = event.get("request_id")

                    if not isinstance(payload, dict):
                        raise ValueError("작업 프로세스 정보가 없습니다.")

                    if request_id is not None and (
                        not isinstance(request_id, str)
                        or not request_id.strip()
                        or len(request_id) > 128
                    ):
                        raise ValueError("등록 요청 ID가 올바르지 않습니다.")

                    try:
                        self._register_process(record, payload)
                    except (ValueError, TypeError) as error:
                        if request_id is not None:
                            await self._send_registration_reply(
                                process, record, request_id, payload, str(error)
                            )
                        raise

                    # 기존 응답 불필요 이벤트는 그대로 지원한다.
                    if request_id is not None:
                        await self._send_registration_reply(
                            process, record, request_id, payload
                        )

                    # 프로세스 등록은 단계 결과를 변경하지 않는다.
                    continue

                # ── 단계 상태 갱신 ──
                if event_type != "step":
                    raise ValueError(f"지원하지 않는 이벤트 종류: {event_type}")

                step = event.get("step")

                if not isinstance(step, dict):
                    raise ValueError("단계 정보가 없습니다.")

                name = step.get("name")
                status = step.get("status")

                if not isinstance(name, str) or name not in allowed_names:
                    raise ValueError("등록되지 않은 작업 이름입니다.")

                if status not in ("running", "passed", "failed"):
                    raise ValueError("잘못된 작업 상태입니다.")

                if step.get("error") is not None and not isinstance(step["error"], str):
                    raise ValueError("작업 오류 메시지는 문자열이어야 합니다.")

                previous = operations.get(name)

                if status == "running":
                    if previous is not None:
                        raise ValueError("중복된 작업 시작 이벤트입니다.")

                elif previous is None or previous["status"] != "running":
                    raise ValueError("작업 시작 없이 완료 이벤트를 받았습니다.")

                operations[name] = dict(step)

                self._map_steps(
                    record,
                    scenario,
                    {"steps": list(operations.values())},
                    final=False,
                )

            except (ValueError, TypeError) as error:
                # 오류가 있어도 stderr는 끝까지 읽어 출력 막힘을 방지한다.
                # 최종적으로는 실행 실패로 처리되도록 오류를 보관한다.
                protocol_error = error

                logger.warning(
                    "Invalid progress event for %s: %s",
                    record.run_id,
                    error,
                )

        if protocol_error is not None:
            raise ValueError(f"진행 이벤트 처리 실패: {protocol_error}")

    @staticmethod
    async def _send_registration_reply(
        process,
        record: RunResponse,
        request_id: str,
        payload: dict,
        error: str | None = None,
    ) -> None:
        """관리 프로세스의 stdin에 한 줄 JSON 등록 결과를 보낸다."""
        if process.stdin is None:
            raise ValueError("등록 응답용 stdin이 연결되지 않았습니다.")

        reply = {
            "type": "process_registered",
            "request_id": request_id,
            "scenario_id": record.scenario_id,
            "status": "rejected" if error is not None else "accepted",
            "role": payload.get("role"),
            "pid": payload.get("pid"),
            "start_time_ticks": payload.get("start_time_ticks"),
            "error": error,
        }
        data = (json.dumps(reply, ensure_ascii=False) + "\n").encode("utf-8")
        try:
            process.stdin.write(data)
            await asyncio.wait_for(process.stdin.drain(), timeout=2.0)
        except (TimeoutError, OSError, RuntimeError) as exc:
            raise ValueError("프로세스 등록 응답을 전달하지 못했습니다.") from exc

    @staticmethod
    def _register_process(
        record: RunResponse,
        payload: dict,
    ) -> None:
        """작업 프로세스를 검증하고 실행 기록에 등록한다.

        # 현재 등록 범위:
        - 시나리오 관리 프로세스 자신
        - 관리 프로세스가 직접 실행한 자식 프로세스

        등록 정보는 종료 권한을 의미하지 않는다.
        실제 종료 시에는 별도 검증이 필요하다.
        """

        worker = RunProcess.model_validate(payload)

        if not worker.role.strip():
            raise ValueError("작업 프로세스 역할이 비어 있습니다.")

        if record.pid is None:
            raise ValueError("시나리오 관리 PID가 아직 없습니다.")

        if worker.start_time_ticks is None:
            raise ValueError("프로세스 시작 정보를 확인할 수 없어 등록하지 않습니다.")

        try:
            content = Path(f"/proc/{worker.pid}/stat").read_text(encoding="utf-8")

        except (FileNotFoundError, ProcessLookupError) as error:
            raise ValueError(
                f"등록할 프로세스가 이미 종료되었습니다: pid={worker.pid}"
            ) from error

        except PermissionError as error:
            raise ValueError(
                f"프로세스 정보를 읽을 권한이 없습니다: pid={worker.pid}"
            ) from error

        try:
            # comm 필드는 공백·괄호를 포함할 수 있으므로
            # 마지막 닫는 괄호 뒤부터 나눈다.
            fields = content.rsplit(")", 1)[1].split()

            parent_pid = int(fields[1])
            actual_start_time = int(fields[19])

        except (IndexError, ValueError) as error:
            raise ValueError(f"프로세스 정보 형식 오류: pid={worker.pid}") from error

        # 같은 PID 번호의 다른 프로세스인지 확인한다.
        if actual_start_time != worker.start_time_ticks:
            raise ValueError("프로세스 시작 정보가 일치하지 않습니다.")

        # 다른 실행의 프로세스를 작업 PID로 등록하지 못하게 제한한다.
        if worker.pid != record.pid and parent_pid != record.pid:
            raise ValueError(
                "작업 프로세스가 시나리오 관리 프로세스의 직접 자식이 아닙니다."
            )

        for existing in record.processes:
            same_identity = (
                existing.pid == worker.pid
                and existing.start_time_ticks == worker.start_time_ticks
            )

            if same_identity:
                if existing.role != worker.role:
                    raise ValueError("같은 프로세스가 다른 역할로 등록되었습니다.")

                # 같은 정보가 다시 도착하면 중복 추가하지 않는다.
                return

            # 현재 설계는 실행당 역할별 프로세스 하나를 사용한다.
            if existing.role == worker.role:
                raise ValueError(f"이미 등록된 작업 역할입니다: {worker.role}")

        # 등록 시각은 서버가 실제로 수신·검증한 시각으로 기록한다.
        worker.registered_at = now()

        record.processes.append(worker)

        logger.info(
            "Registered process: run=%s role=%s pid=%s start=%s",
            record.run_id,
            worker.role,
            worker.pid,
            worker.start_time_ticks,
        )

    async def _collect_output(
        self,
        process,
        record: RunResponse,
        scenario: Scenario,
    ):
        """최종 stdout 수집과 실시간 stderr 읽기를 동시에 수행한다."""
        results = await asyncio.gather(
            process.stdout.read(),
            self._read_progress(process, record, scenario),
            process.wait(),
            return_exceptions=True,
        )

        # 모든 스트림을 정리한 뒤 오류를 상위 실행 처리에 전달한다.
        for result in results:
            if isinstance(result, BaseException):
                raise result

        return results[0]

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

            command = [
                sys.executable,
                "-u",
                "-m",
                scenario.module,
            ]
            # API 실행에서만 PID 등록 승인을 기다린다.
            if scenario.module == "scenarios.s01_normal":
                command.append("--wait-registration-ack")

            process = await asyncio.create_subprocess_exec(
                *command,
                cwd=str(PROJECT_ROOT),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                # Linux에서는 시나리오를 새로운 세션으로 실행한다.
                # 시나리오 PID가 새 세션 ID와 프로세스 그룹 ID가 된다.
                # Windows에서는 기존 실행 방식을 유지한다.
                start_new_session=(sys.platform == "linux"),
            )

            record.pid = process.pid

            # stdout은 최종 JSON, stderr는 실시간 진행 이벤트로 읽는다.
            communication = asyncio.create_task(
                self._collect_output(
                    process,
                    record,
                    scenario,
                )
            )

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

            stdout = communication.result()

            # 최종 결과는 기존 방식대로 검증한다.
            result = json.loads(stdout.decode("utf-8"))

            self._validate_result(result, record, scenario)

            record.result = result
            record.holdfs_pid = result.get(
                "holdfs_pid",
                result.get("guardfs_pid"),
            )

            # 최종 JSON을 기준으로 단계 결과를 다시 확정한다.
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
                        if process is not None and process.returncode is not None:
                            # 출력/이벤트 처리 실패와 프로세스 종료 실패는 다르다.
                            # 이미 종료된 경우에는 원래 오류를 보존하고 새 실행을 허용한다.
                            logger.warning(
                                "종료된 테스트의 출력 처리 실패: %s",
                                record.run_id,
                                exc_info=True,
                            )
                        else:
                            self._cleanup_blocked = True
                            logger.exception("테스트 종료 확인 실패: %s", record.run_id)
                            record.status = "failed"
                            record.error = (
                                "테스트 종료 확인 실패로 새 실행을 차단했습니다."
                            )
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
                    if step.status == "running":
                        step.status = "failed"
                        step.error = (
                            record.error
                            or "단계 완료를 확인하기 전에 실행이 종료됐습니다."
                        )
                    elif step.status == "pending":
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
        final: bool = True,
    ):
        """세부 작업들을 카탈로그의 화면 단계로 묶는다."""
        operations = {operation["name"]: operation for operation in result["steps"]}

        for definition, step in zip(scenario.steps, record.steps):
            matched = [
                operations[name]
                for name in definition.operation_names
                if name in operations
            ]

            # 이전 오류가 다음 갱신에 잘못 남지 않게 초기화한다.
            step.error = None

            failed = next(
                (operation for operation in matched if operation["status"] == "failed"),
                None,
            )

            if failed:
                step.status = "failed"
                step.error = failed.get("error") or f"{failed['name']} 작업 실패"
            elif (
                definition.operation_names
                and len(matched) == len(definition.operation_names)
                and all(operation["status"] == "passed" for operation in matched)
            ):
                # 묶인 작업이 모두 성공해야 화면 단계도 완료 처리한다.
                step.status = "passed"
            elif final:
                # 실행 종료 후 완료되지 않은 단계이다.
                step.status = "skipped"
            elif matched:
                # 일부 작업이 시작되거나 완료됐지만 단계 전체는 미완료이다.
                step.status = "running"
            else:
                step.status = "pending"
