"""
backend/app/services/runner.py

- 단일 서버 프로세스에서 S01 실행 및 결과 관리
"""

import asyncio
import json
import logging
import math
import os
import signal
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

from guardfs.common.paths import (
    FILESECURITY_LOG_PATH,
    PROJECT_ROOT as HOLDFS_PROJECT_ROOT,
    get_event_log_path,
)
from scenarios.catalog import Scenario, get_scenario
from scenarios.common import get_runtime_paths
from scenarios.execution import get_execution
from scenarios.results import validate_result_details

from ..schemas.run import (
    RunCreatedResponse,
    RunEventCollection,
    RunProcess,
    RunResponse,
    RunStepResponse,
    RunWorkspace,
)
from .holdfs_events import (
    EventScope,
    LogCheckpoint,
    capture_log,
    collect_events,
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
        *,
        mount_path: str | Path | None = None,
        underlay_path: str | Path | None = None,
    ):
        if not all(
            math.isfinite(value) and value > 0
            for value in (timeout_seconds, cleanup_seconds)
        ):
            raise ValueError("실행 및 종료 대기 시간은 양수여야 합니다.")

        default_mount, default_underlay = get_runtime_paths()
        mount = default_mount if mount_path is None else Path(mount_path)
        underlay = default_underlay if underlay_path is None else Path(underlay_path)

        # S01과 동일하게 mount 경로는 유지하고 underlay는 실제 경로로 정규화한다.
        self.mount_path = Path(os.path.abspath(mount.expanduser()))
        self.underlay_path = underlay.expanduser().resolve()

        self.timeout_seconds = timeout_seconds
        self.cleanup_seconds = cleanup_seconds

        self._runs: dict[str, RunResponse] = {}
        self._cancel_events: dict[str, asyncio.Event] = {}
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

        execution = get_execution(scenario.id, scenario.module)

        if execution is None:
            raise ScenarioUnavailableError("실행 연결이 구현되지 않은 시나리오입니다.")

        if self._cleanup_blocked:
            raise RunBusyError(
                "이전 테스트의 종료를 확인하지 못했습니다. HoldFS와 PID를 점검하세요."
            )

        if self._active_task and not self._active_task.done():
            raise RunBusyError("다른 테스트가 실행 중입니다.")

        # API의 async 핸들러에서 호출해야 한다. 실패한 예약 기록은 남기지 않는다.
        loop = asyncio.get_running_loop()
        run_id = uuid.uuid4().hex

        # 최종 결과가 없는 중단 실행도 로그 수집 경로를 알 수 있도록 미리 기록한다.
        work_dir_name = execution.workspace_name(run_id)
        workspace = RunWorkspace(
            name=work_dir_name,
            mount_path=str(self.mount_path / work_dir_name),
            underlay_path=str(self.underlay_path / work_dir_name),
        )

        record = RunResponse(
            run_id=run_id,
            scenario_id=scenario.id,
            status="queued",
            created_at=now(),
            workspace=workspace,
            steps=[
                RunStepResponse(id=step.id, name=step.name) for step in scenario.steps
            ],
        )
        self._runs[run_id] = record
        self._cancel_events[run_id] = asyncio.Event()

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
        """최종 정리와 이벤트 수집이 끝난 뒤 완료 상태를 공개한다."""
        if run_id not in self._runs:
            raise KeyError(run_id)

        record = self._runs[run_id].model_copy(deep=True)
        if record.finished_at is None and record.status in {
            "passed",
            "failed",
            "timed_out",
            "cancelled",
        }:
            cancel_event = self._cancel_events.get(run_id)
            record.status = (
                "cancelling"
                if cancel_event is not None and cancel_event.is_set()
                else "running"
            )
        return record

    def cancel(self, run_id: str) -> RunResponse:
        """테스트 프로세스 그룹의 종료를 요청한다.

        프로세스 정리는 실행 태스크가 수행한다.
        HoldFS의 상태 전이, staging, 지연 반영 정책은 변경하지 않는다.
        """

        if run_id not in self._runs:
            raise KeyError(run_id)

        record = self._runs[run_id]

        # 이미 완료됐거나 중단 요청을 받은 실행은 현재 상태를 반환한다.
        # 다른 실행의 중단 이벤트에는 영향을 주지 않는다.
        if record.status not in ("queued", "running"):
            return self.get(run_id)

        event = self._cancel_events[run_id]

        record.status = "cancelling"
        event.set()

        # 응답은 ‘중단 요청 접수’이지 ‘프로세스 종료 완료’가 아니다.
        return self.get(run_id)

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

    @staticmethod
    def _group_exists(pgid: int) -> bool:
        """그룹이 존재하는지 확인한다. 권한 오류는 종료 확인 실패로 전달한다."""

        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return False

        return True

    @staticmethod
    def _signal_group(pgid: int, sig: int) -> None:
        """존재하는 그룹에 신호를 보낸다."""

        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            # 확인 직후 그룹이 종료되는 경우는 정상이다.
            return

    async def _wait_group_exit(
        self,
        process,
        pgid: int,
        timeout_seconds: float,
    ) -> bool:
        """관리자 종료와 그룹 소멸을 함께 기다린다."""

        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_seconds

        while True:
            group_exists = self._group_exists(pgid)

            # 관리자가 종료되어도 자식이 남으면 완료로 판단하지 않는다.
            if process.returncode is not None and not group_exists:
                await process.wait()
                return True

            remaining = deadline - loop.time()

            if remaining <= 0:
                return False

            await asyncio.sleep(min(0.05, remaining))

    async def _terminate_process_group(self, process) -> None:
        """
        이 runner가 독립 세션으로 생성한 실행 그룹을 종료한다.

        등록된 작업 PID 목록으로 종료 대상을 구성하지 않는다.
        create_subprocess_exec()가 반환한 관리자 PID만 그룹 ID로 사용한다.
        """

        if sys.platform != "linux":
            # Windows에서는 기존 관리자 단독 종료 동작을 유지한다.
            # 전체 그룹 정리는 Linux에서 지원한다.
            if process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass

            await asyncio.wait_for(
                process.wait(),
                timeout=self.cleanup_seconds,
            )
            return

        pgid = process.pid

        # runner 자신의 그룹으로 신호가 전달되는 것을 방지한다.
        if pgid <= 1 or pgid == os.getpgrp():
            raise RuntimeError("안전하지 않은 실행 그룹 ID입니다.")

        # 관리자가 아직 존재한다면 독립 세션·그룹인지 다시 확인한다.
        try:
            actual_pgid = os.getpgid(process.pid)
            actual_sid = os.getsid(process.pid)
        except ProcessLookupError:
            # 관리자가 먼저 종료돼도 자식 그룹은 남을 수 있다.
            pass
        else:
            if actual_pgid != pgid or actual_sid != pgid:
                raise RuntimeError(
                    "관리자가 독립 실행 그룹에 속하지 않아 종료를 중단했습니다."
                )

        if self._group_exists(pgid):
            # 먼저 정상 종료를 요청한다.
            self._signal_group(pgid, signal.SIGTERM)

            # SIGSTOP 상태의 프로세스도 종료 요청을 처리하도록 재개한다.
            self._signal_group(pgid, signal.SIGCONT)

        if await self._wait_group_exit(
            process,
            pgid,
            self.cleanup_seconds,
        ):
            return

        # 정상 종료 요청을 따르지 않는 프로세스는 강제 종료한다.
        self._signal_group(pgid, signal.SIGKILL)

        if not await self._wait_group_exit(
            process,
            pgid,
            self.cleanup_seconds,
        ):
            raise TimeoutError(f"실행 그룹 종료를 확인하지 못했습니다: pgid={pgid}")

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

    def _capture_event_logs(
        self,
    ) -> tuple[list[LogCheckpoint], list[str]]:
        """실행 전 로그 위치를 기록한다. 각 로그는 독립적으로 확인한다."""

        checkpoints = []
        issues = []

        sources = (
            (
                "filesystem",
                get_event_log_path(str(self.underlay_path)),
            ),
            (
                "policy",
                FILESECURITY_LOG_PATH,
            ),
        )

        for source, path in sources:
            try:
                checkpoints.append(capture_log(path, source))
            except (OSError, ValueError) as error:
                # 하나를 읽지 못해도 다른 로그의 수집은 시도한다.
                issues.append(f"{source} 로그 시작 위치 확인 실패: {error}")

        return checkpoints, issues

    def _collect_run_events(
        self,
        record: RunResponse,
        checkpoints: list[LogCheckpoint],
        capture_issues: list[str],
        started_at_ns: int | None,
    ) -> RunEventCollection:
        """등록된 PID와 고유 작업 경로로 이벤트 후보를 수집한다."""

        observed_until_ns = time.time_ns()

        report = RunEventCollection(
            observed_at=now(),
            filesystem_until_ns=observed_until_ns,
            captured_sources=[checkpoint.source for checkpoint in checkpoints],
            issues=list(capture_issues),
        )

        if started_at_ns is None:
            report.issues.append(
                "프로세스 실행 전 종료되어 이벤트 수집을 시작하지 않았습니다."
            )
            return report

        if record.workspace is None:
            report.issues.append("이벤트를 연결할 작업 경로가 없습니다.")
            return report

        # 검증·등록된 작업 PID만 사용한다.
        # 관리자 PID를 무조건 작업 PID로 간주하지 않는다.
        pids = frozenset(process.pid for process in record.processes)

        if not pids:
            report.issues.append("등록된 작업 프로세스가 없어 수집하지 않았습니다.")
            return report

        scope = EventScope(
            pids=pids,
            roots=(
                record.workspace.mount_path,
                record.workspace.underlay_path,
            ),
            started_at_ns=started_at_ns,
            observed_until_ns=observed_until_ns,
        )

        for checkpoint in checkpoints:
            try:
                collected = collect_events(checkpoint, scope)
            except Exception as error:
                # 로그별 오류를 보고하고 나머지 로그 수집은 계속한다.
                # 수집 모듈의 예상하지 못한 예외도 파일 작업 결과와 분리한다.
                logger.exception(
                    "%s 이벤트 수집 실패: %s",
                    checkpoint.source,
                    record.run_id,
                )
                report.issues.append(
                    f"{checkpoint.source} 이벤트 수집 중 예외 발생: "
                    f"{type(error).__name__}: {error}"
                )
                continue

            report.events.extend(collected.events)
            report.pid_only_events.extend(collected.pid_only_events)
            report.issues.extend(collected.issues)

            report.pending_record = report.pending_record or collected.pending_record

        return report

    async def _execute(
        self,
        record: RunResponse,
        scenario: Scenario,
    ):
        process = None
        communication = None
        stop_wait = None
        cancel_wait = None
        checkpoints: list[LogCheckpoint] = []
        capture_issues: list[str] = []
        event_started_at_ns: int | None = None

        cancel_event = self._cancel_events[record.run_id]
        cancelled_by_user = False

        # queued 상태에서 바로 중단 요청을 받은 경우도 처리한다.
        if not cancel_event.is_set():
            record.status = "running"

        record.started_at = now()

        try:
            if self._stop.is_set():
                record.status = "failed"
                record.error = "서버 종료로 실행을 취소했습니다."
                return

            if cancel_event.is_set():
                cancelled_by_user = True
                record.status = "cancelling"
                record.error = "사용자가 테스트 프로세스 종료를 요청했습니다."
                return

            execution = get_execution(scenario.id, scenario.module)

            if execution is None:
                raise ScenarioUnavailableError(
                    "실행 연결이 구현되지 않은 시나리오입니다."
                )

            if record.workspace is None:
                raise ValueError("실행 작업 경로가 설정되지 않았습니다.")

            command = execution.build_command(
                mount=self.mount_path,
                underlay=self.underlay_path,
                work_dir_name=record.workspace.name,
            )

            # 파일 읽기는 스레드에서 수행하고 수집 실패는 실행 결과와 분리한다.
            try:
                checkpoints, capture_issues = await asyncio.to_thread(
                    self._capture_event_logs
                )
            except Exception as error:
                logger.exception("로그 시작 위치 확인 실패: %s", record.run_id)
                capture_issues.append(
                    f"로그 시작 위치 확인 중 예외 발생: {type(error).__name__}: {error}"
                )

            # 로그 확인을 기다리는 동안 들어온 종료 요청도 생성 전에 반영한다.
            if self._stop.is_set():
                record.status = "failed"
                record.error = "서버 종료로 실행을 취소했습니다."
                return
            if cancel_event.is_set():
                cancelled_by_user = True
                record.status = "cancelling"
                record.error = "사용자가 테스트 프로세스 종료를 요청했습니다."
                return

            event_started_at_ns = time.time_ns()
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
            cancel_wait = asyncio.create_task(cancel_event.wait())

            done, _ = await asyncio.wait(
                {communication, stop_wait, cancel_wait},
                timeout=self.timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )

            # 결과 수집이 이미 완료됐다면 최종 결과 처리를 우선한다.
            # 완료와 중단 요청이 거의 동시에 발생한 경우의 기준이다.
            if communication not in done:
                if stop_wait in done:
                    record.status = "failed"
                    record.error = "서버 종료로 테스트를 중단했습니다."
                    return

                if cancel_wait in done:
                    cancelled_by_user = True
                    record.status = "cancelling"
                    record.error = "사용자가 테스트 프로세스 종료를 요청했습니다."
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

            if result["status"] == "timed_out":
                record.status = "timed_out"
                record.error = next(
                    (step.error for step in record.steps if step.error),
                    "시나리오 작업 제한 시간을 초과했습니다.",
                )
            elif (
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
                waiters = [
                    task for task in (stop_wait, cancel_wait) if task is not None
                ]

                for task in waiters:
                    task.cancel()

                if waiters:
                    await asyncio.gather(
                        *waiters,
                        return_exceptions=True,
                    )

                if process is not None:
                    try:
                        # 정상 종료 후에도 자식이 남았는지 확인한다.
                        await self._terminate_process_group(process)

                    except (OSError, RuntimeError, TimeoutError) as error:
                        self._cleanup_blocked = True

                        # 시간 초과는 기존 timed_out 상태를 유지한다.
                        if record.status != "timed_out":
                            record.status = "failed"

                        message = (
                            f"실행 그룹 정리 실패: {error}. "
                            "종료를 확인하지 못해 새 실행을 차단했습니다."
                        )

                        record.error = (
                            f"{record.error} {message}" if record.error else message
                        )

                        logger.exception(
                            "실행 그룹 정리 실패: %s",
                            record.run_id,
                        )

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
                # 그룹 정리가 확인된 경우에만 테스트 실행 중단을 확정한다.
                if cancelled_by_user:
                    # 종료 확인 실패는 중단 진행 상태로 남기지 않는다.
                    # 새 실행 차단은 유지하고 최종 실패로 알린다.
                    if self._cleanup_blocked:
                        record.status = "failed"
                    else:
                        # 프로세스 실행만 중단한다. HoldFS의 후속 처리는 계속될 수 있다.
                        record.status = "cancelled"
                        record.error = (
                            "사용자 요청으로 테스트 프로세스 실행을 중단했습니다. "
                            "이미 접수된 작업은 HoldFS 정책에 따라 처리됩니다."
                        )

                for step in record.steps:
                    if step.status == "running":
                        if record.status == "cancelled":
                            # 중간에 멈춘 단계는 검증 실패로 단정하지 않는다.
                            step.status = "skipped"
                            step.error = None
                        else:
                            step.status = "failed"
                            step.error = (
                                record.error
                                or "단계 완료를 확인하기 전에 실행이 종료됐습니다."
                            )

                    elif step.status == "pending":
                        step.status = "skipped"

                try:
                    # 현재까지의 관찰 결과다. HoldFS 후속 처리 완료를 뜻하지 않는다.
                    record.event_collection = await asyncio.to_thread(
                        self._collect_run_events,
                        record.model_copy(deep=True),
                        checkpoints,
                        capture_issues,
                        event_started_at_ns,
                    )
                except Exception as error:
                    logger.exception("실행 이벤트 수집 실패: %s", record.run_id)
                    record.event_collection = RunEventCollection(
                        observed_at=now(),
                        captured_sources=[item.source for item in checkpoints],
                        issues=[
                            *capture_issues,
                            f"이벤트 수집 중 예외 발생: {type(error).__name__}: {error}",
                        ],
                    )
                finally:
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

        if result.get("status") not in ("passed", "failed", "timed_out"):
            raise ValueError("잘못된 테스트 상태입니다.")

        validate_result_details(result)

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
