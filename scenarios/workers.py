"""등록 확인 후 자식 작업을 시작하는 공통 도구."""

import math
import subprocess
import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from typing import Any

from scenarios.common import register_process_and_wait


def stop_worker(
    process: subprocess.Popen,
    timeout_seconds: float = 3.0,
) -> None:
    """자식 하나를 종료하고 회수한다. 프로세스 그룹 종료는 후속 작업이다."""

    if process.poll() is not None:
        process.wait()
        return

    process.terminate()

    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=timeout_seconds)


@contextmanager
def registered_worker(
    scenario_id: str,
    role: str,
    command: Sequence[str],
    *,
    registration_timeout: float = 5.0,
    capture_stdout: bool = False,
) -> Iterator[tuple[subprocess.Popen, dict[str, Any]]]:
    """자식을 등록하고 시작시킨 뒤, 사용이 끝나면 종료 상태를 회수한다."""

    if sys.platform != "linux":
        raise RuntimeError("자식 작업 실행은 Linux에서 지원합니다.")

    if not command or isinstance(command, (str, bytes)):
        raise ValueError("실행 명령은 비어 있지 않은 문자열 목록이어야 합니다.")

    if any(not isinstance(arg, str) or not arg for arg in command):
        raise ValueError("실행 명령의 각 항목은 비어 있지 않은 문자열이어야 합니다.")

    if not scenario_id or not role.strip():
        raise ValueError("시나리오 ID와 작업 역할이 필요합니다.")

    if not math.isfinite(registration_timeout) or registration_timeout <= 0:
        raise ValueError("등록 대기 시간은 양수여야 합니다.")

    process = subprocess.Popen(
        [
            sys.executable,
            "-u",
            "-m",
            "scenarios.child_gate",
            "--",
            *command,
        ],
        stdin=subprocess.PIPE,
        # 시나리오 관리자의 stdout은 최종 JSON 전용이다.
        # 자식의 일반 출력을 섞지 않는다.
        stdout=(subprocess.PIPE if capture_stdout else subprocess.DEVNULL),
        # 오류 메시지는 관리자의 stderr로 전달한다.
        stderr=None,
        # runner가 만든 프로세스 그룹을 그대로 상속한다.
        start_new_session=False,
    )

    try:
        # 이 함수는 시나리오 관리자에서 호출된다.
        # 이벤트의 발신 PID는 관리자, 등록 대상 PID는 자식이다.
        metadata = register_process_and_wait(
            scenario_id,
            role,
            pid=process.pid,
            timeout_seconds=registration_timeout,
        )

        if process.poll() is not None:
            raise RuntimeError(
                f"등록 중 자식 프로세스가 종료됐습니다: pid={process.pid}"
            )

        if process.stdin is None:
            raise RuntimeError("자식의 시작 제어 통로가 없습니다.")

        try:
            # 등록 성공 응답을 받은 다음에만 시작 신호를 전달한다.
            process.stdin.write(b"START\n")
            process.stdin.flush()
        finally:
            process.stdin.close()

        yield process, metadata

    finally:
        # 등록 실패나 본문 예외가 발생해도 자식을 남기지 않는다.
        # 먼저 종료해, 시작 신호를 기다리던 자식도 회수한다.
        try:
            stop_worker(process)
        finally:
            if process.stdin is not None and not process.stdin.closed:
                process.stdin.close()
