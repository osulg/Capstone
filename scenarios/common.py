"""
# HoldFS 시나리오의 공통 이벤트 출력 도구.

stderr:
    PROGRESS 접두사가 붙은 한 줄 JSON 이벤트

stdout:
    각 시나리오가 최종 결과 JSON을 출력하는 용도로 유지
"""

import json
import math
import os
import selectors
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def timestamp() -> str:
    """UTC 기준 ISO 형식 시각을 반환한다."""

    return datetime.now(UTC).isoformat()


def get_process_start_time(pid: int) -> int | None:
    """
    Linux 프로세스의 시작 tick을 읽는다.

    PID는 재사용될 수 있으므로 PID와 시작 tick을 함께 기록한다.
    프로세스가 이미 종료됐거나 정보를 읽을 수 없으면 None을 반환한다.
    """
    if pid <= 0:
        raise ValueError("PID는 양수여야 합니다.")

    try:
        content = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")

        # 두 번째 필드 comm은 괄호 안에 있으며 공백도 포함할 수 있다.
        # 마지막 닫는 괄호 뒤부터 분리해야 필드 위치가 유지된다.
        fields = content.rsplit(")", 1)[1].split()

        # /proc/<pid>/stat의 22번째 필드 starttime.
        # fields는 3번째 필드 state부터 시작하므로 인덱스는 19다.
        return int(fields[19])

    except (
        FileNotFoundError,
        ProcessLookupError,
        PermissionError,
    ):
        return None

    except (IndexError, ValueError) as error:
        raise RuntimeError(
            f"프로세스 시작 정보 형식이 올바르지 않습니다: pid={pid}"
        ) from error


def _emit_event(event: dict[str, Any]) -> None:
    """runner가 읽을 이벤트를 stderr에 즉시 출력한다."""

    line = "PROGRESS " + json.dumps(
        event,
        ensure_ascii=False,
    )

    print(
        line,
        file=sys.stderr,
        flush=True,
    )


def emit_progress(
    scenario_id: str,
    step: dict[str, Any],
) -> None:
    """단계 시작·성공·실패 이벤트를 출력한다."""

    if not scenario_id:
        raise ValueError("시나리오 ID가 필요합니다.")

    if not isinstance(step.get("name"), str) or not step["name"]:
        raise ValueError("작업 이름이 필요합니다.")

    if step.get("status") not in ("running", "passed", "failed"):
        raise ValueError("잘못된 작업 상태입니다.")

    _emit_event(
        {
            "type": "step",
            "scenario_id": scenario_id,
            "pid": os.getpid(),  # 이벤트를 출력한 시나리오 관리 프로세스 PID
            "step": dict(step),
        }
    )


def emit_process(
    scenario_id: str,
    role: str,
    pid: int | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    """
    작업 프로세스 등록 이벤트를 출력하고 등록 정보를 반환한다.

    # pid 생략:
        시나리오가 직접 파일 작업을 수행하는 경우 자신의 PID 등록

    # pid 지정:
        시나리오 관리 프로세스가 실행한 자식 작업 프로세스 등록
    """

    if not scenario_id:
        raise ValueError("시나리오 ID가 필요합니다.")

    if not role.strip():
        raise ValueError("프로세스 역할이 필요합니다.")

    worker_pid = os.getpid() if pid is None else pid

    if worker_pid <= 0:
        raise ValueError("작업 PID는 양수여야 합니다.")

    process = {
        "role": role,
        "pid": worker_pid,
        "start_time_ticks": get_process_start_time(worker_pid),
        "registered_at": timestamp(),
    }

    event = {
        "type": "process",
        "scenario_id": scenario_id,
        "pid": os.getpid(),
        "process": process,
    }
    if request_id is not None:
        event["request_id"] = request_id
    _emit_event(event)

    return process


def register_process_and_wait(
    scenario_id: str,
    role: str,
    pid: int | None = None,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    """
    Linux runner의 PID 등록 승인을 기다린다.
    한 번에 한 요청만 지원한다.

    stdin은 응답 전용으로 사용하고 input()/readline()과 혼용하지 않는다.
    직접 실행에서는 응답을 기다리지 않는 emit_process()를 사용한다.
    """

    if sys.platform != "linux":
        raise RuntimeError("등록 응답 대기는 Linux에서 지원합니다.")

    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("응답 대기 시간은 양수여야 합니다.")

    stdin_fd = sys.stdin.fileno()
    request_id = uuid.uuid4().hex

    # Linux의 기본 epoll은 /dev/null 같은 fd를 등록할 때 EPERM을 낼 수 있다.
    # poll은 실제 runner의 파이프와 EOF 확인용 /dev/null 모두 처리한다.
    with selectors.PollSelector() as selector:
        selector.register(stdin_fd, selectors.EVENT_READ)
        process = emit_process(scenario_id, role, pid, request_id=request_id)
        deadline = time.monotonic() + timeout_seconds
        buffer = bytearray()

        while b"\n" not in buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(timeout=remaining):
                raise RuntimeError("PID 등록 응답 시간이 초과됐습니다.")

            chunk = os.read(stdin_fd, 4096)
            if not chunk:
                raise RuntimeError("runner의 등록 응답 통로가 종료됐습니다.")

            buffer.extend(chunk)
            if len(buffer) > 16384:
                raise RuntimeError("등록 응답이 허용 크기를 초과했습니다.")

    line, _, remainder = buffer.partition(b"\n")

    if remainder.strip():
        raise RuntimeError("예상하지 않은 추가 등록 응답입니다.")
    try:
        reply = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("등록 응답이 올바른 JSON이 아닙니다.") from error

    if not isinstance(reply, dict):
        raise RuntimeError("등록 응답이 객체가 아닙니다.")
    if (
        reply.get("type") != "process_registered"
        or reply.get("request_id") != request_id
        or reply.get("scenario_id") != scenario_id
    ):
        raise RuntimeError("등록 응답이 현재 요청과 일치하지 않습니다.")

    if reply.get("status") == "rejected":
        raise RuntimeError(f"PID 등록 거절: {reply.get('error')}")

    if reply.get("status") != "accepted":
        raise RuntimeError("알 수 없는 등록 응답 상태입니다.")

    if any(
        reply.get(key) != process[key] for key in ("role", "pid", "start_time_ticks")
    ):
        raise RuntimeError("등록된 프로세스 식별 정보가 다릅니다.")

    return process
