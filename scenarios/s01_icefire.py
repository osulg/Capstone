"""IceFire 준비·공개 확인·공격 모의 작업 관리자.

--run-attack 지정 시 준비·공개 확인 이후 공격 모의 작업을 수행한다.
runner의 PID 등록 응답 통로가 있는 실행 환경에서 사용한다.
"""

import argparse
import json
import math
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path

from scenarios.common import (
    emit_progress,
    get_runtime_paths,
    register_process_and_wait,
    timestamp,
)
from scenarios.results import validate_result_details
from scenarios.icefire_config import (
    FILE_COUNT, FILE_SIZE_KIB, PREPARE_TIMEOUT_SECONDS,
    ATTACK_TIMEOUT_SECONDS, WORKER_PYTHON, expected_operations,
)
from scenarios.s01_normal import check_health, find_guardfs_pid
from scenarios.workers import registered_worker

SCENARIO_ID = "S01"


def validate_task_result(payload, action, returncode):
    """자식 JSON의 작업 종류·연산 수·종료 상태를 검사한다."""
    if not isinstance(payload, dict):
        raise ValueError("자식 결과가 JSON 객체가 아닙니다.")
    if payload.get("action") != action:
        raise ValueError("자식 결과의 작업 종류가 일치하지 않습니다.")

    reasons = {
        "passed": "completed",
        "failed": "operation_failed",
        "timed_out": "deadline_exceeded",
    }
    status = payload.get("status")
    if not isinstance(status, str) or status not in reasons:
        raise ValueError("잘못된 자식 결과 상태입니다.")
    if type(returncode) is not int or (returncode == 0) != (status == "passed"):
        raise ValueError("자식 종료 코드와 결과 상태가 일치하지 않습니다.")

    validate_result_details(
        {
            "result_version": 2,
            "status": status,
            "termination_reason": reasons[status],
            "steps": [
                {
                    "name": action.upper(),
                    "status": "passed" if status == "passed" else "failed",
                    "planned": payload.get("planned"),
                    "attempted": payload.get("attempted"),
                    "completed": payload.get("completed"),
                    "failure": payload.get("failure"),
                }
            ],
        }
    )
    if payload["planned"] != expected_operations(action):
        raise ValueError("자식 결과의 예정 연산 수가 일치하지 않습니다.")
    return payload


def parse_args():
    mount, underlay = get_runtime_paths()

    parser = argparse.ArgumentParser()
    parser.add_argument("--mount", type=Path, default=mount)
    parser.add_argument("--underlay", type=Path, default=underlay)
    parser.add_argument(
        "--holdfs-pid",
        "--guardfs-pid",
        dest="holdfs_pid",
        type=int,
    )
    parser.add_argument(
        "--work-dir-name",
        default=f"s01_{uuid.uuid4().hex}",
    )
    parser.add_argument("--prepare-timeout", type=float, default=PREPARE_TIMEOUT_SECONDS)
    parser.add_argument("--attack-timeout", type=float, default=ATTACK_TIMEOUT_SECONDS)
    parser.add_argument("--worker-python", type=Path, default=WORKER_PYTHON)
    parser.add_argument("--wait-registration-ack", action="store_true")
    parser.add_argument("--run-attack", action="store_true",
                        help="준비·공개 확인 성공 후 공격 모의 작업을 실행합니다.")
    args = parser.parse_args()

    if not args.wait_registration_ack:
        parser.error("현재 관리자는 runner 등록 응답 통로가 필요합니다.")

    if re.fullmatch(r"s01_[0-9a-f]{32}", args.work_dir_name) is None:
        parser.error("작업 폴더 이름은 s01_ 뒤에 소문자 16진수 32자리입니다.")

    if not math.isfinite(args.prepare_timeout) or args.prepare_timeout <= 0:
        parser.error("준비 제한 시간은 유한한 양수여야 합니다.")

    if args.holdfs_pid is not None and args.holdfs_pid <= 0:
        parser.error("HoldFS PID는 양수여야 합니다.")

    if not math.isfinite(args.attack_timeout) or args.attack_timeout <= 0:
        parser.error("공격 제한 시간은 유한한 양수여야 합니다.")

    return args


def run(args):
    mount = Path(os.path.abspath(args.mount.expanduser()))
    underlay = args.underlay.expanduser().resolve()
    workdir = mount / args.work_dir_name
    run_attack = getattr(args, "run_attack", False)
    worker_python = Path(getattr(args, "worker_python", WORKER_PYTHON)).expanduser().absolute()
    attack_timeout = getattr(args, "attack_timeout", ATTACK_TIMEOUT_SECONDS)

    report = {
        "result_version": 2,
        "scenario_id": SCENARIO_ID,
        "pid": os.getpid(),
        "status": "failed",
        "termination_reason": "operation_failed",
        "execution_scope": "full" if run_attack else "prepare_only",
        "attack_started": False,
        "execution_settings": {
            "files": FILE_COUNT,
            "size_kib": FILE_SIZE_KIB,
            "worker_python": str(worker_python),
            "prepare_timeout_seconds": args.prepare_timeout,
            "attack_timeout_seconds": attack_timeout,
        },
        "started_at": timestamp(),
        "finished_at": None,
        "holdfs_pid": None,
        "workspace": {
            "mount_path": str(workdir),
            "underlay_path": str(underlay / args.work_dir_name),
        },
        "processes": [],
        "steps": [],
        "task_results": [],
        "detection_verification": "not_checked",
    }

    current_name = "PRECHECK"
    current_path = mount
    holdfs_pid = args.holdfs_pid

    def progress(status, **details):
        emit_progress(
            SCENARIO_ID,
            {
                "name": current_name,
                "status": status,
                **details,
            },
        )

    def completed_step():
        # 화면 단계는 처리 1회를 세고, 연산별 집계는 task_results에 보존한다.
        step = {
            "name": current_name,
            "status": "passed",
            "planned": 1,
            "attempted": 1,
            "completed": 1,
            "failure": None,
        }
        report["steps"].append(step)
        progress("passed")

    def run_worker(action, role):
        timeout = attack_timeout if action == "attack" else args.prepare_timeout
        command = [
            str(worker_python),
            "-u",
            "-m",
            "scenarios.icefire_tasks",
            action,
            "--workdir",
            str(workdir),
            "--files",
            str(FILE_COUNT),
            "--size-kb",
            str(FILE_SIZE_KIB),
            "--timeout",
            str(timeout),
        ]

        # 관리자가 등록 응답을 받은 다음에만 자식에게 START를 보낸다.
        with registered_worker(
            SCENARIO_ID,
            role,
            command,
            capture_stdout=True,
        ) as (process, metadata):
            report["processes"].append(metadata)
            if action == "attack":
                # 등록 승인 이후 START가 전송된 시점이며 파일 변조 완료는 아니다.
                report["attack_started"] = True
            # START 전송 후 닫힌 stdin을 communicate가 다시 flush하지 않게 한다.
            if process.stdin is not None and process.stdin.closed:
                process.stdin = None
            stdout, _ = process.communicate(timeout=timeout + 1.0)
            try:
                payload = json.loads(stdout.decode("utf-8"))
                payload = validate_task_result(payload, action, process.returncode)
            except (UnicodeDecodeError, ValueError) as error:
                raise RuntimeError(f"{role} 결과 형식 오류: {error}") from error

            report["task_results"].append(payload)
            if payload["status"] == "timed_out":
                raise subprocess.TimeoutExpired(command, timeout)
            if payload["status"] != "passed":
                raise RuntimeError(f"{role} 실패: {payload['failure']['message']}")

        check_health(mount, holdfs_pid)

    try:
        progress("running")

        if sys.platform != "linux":
            raise RuntimeError("Linux에서 실행해야 합니다.")

        if holdfs_pid is None:
            holdfs_pid = find_guardfs_pid()

        check_health(mount, holdfs_pid)

        if not underlay.is_dir():
            raise RuntimeError("underlay 디렉터리가 없습니다.")

        if not worker_python.is_file() or not os.access(worker_python, os.X_OK):
            raise RuntimeError(f"작업 Python을 실행할 수 없습니다: {worker_python}")

        if mount.resolve() == underlay:
            raise RuntimeError("mount와 underlay는 서로 달라야 합니다.")

        report["holdfs_pid"] = holdfs_pid

        # 이후 mkdir도 관리자 PID에 연결되도록 먼저 등록한다.
        metadata = register_process_and_wait(
            SCENARIO_ID,
            "icefire_manager",
        )
        report["processes"].append(metadata)
        completed_step()

        current_name = "PREPARE"
        current_path = workdir
        progress("running")

        # 기존 경로를 재사용하지 않는다.
        workdir.mkdir(exist_ok=False)

        run_worker("prepare", "icefire_prepare")
        completed_step()

        current_name = "VERIFY_READY"
        progress("running")

        run_worker("verify", "icefire_verify")
        completed_step()

        if run_attack:
            current_name = "ACTION"
            current_path = workdir
            progress("running")
            run_worker("attack", "icefire_attack")
            completed_step()

        # 요청한 실행 범위의 작업 완료이며 탐지·보호 성공은 별도 검증한다.
        report["status"] = "passed"
        report["termination_reason"] = "completed"

    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        timed_out = isinstance(error, subprocess.TimeoutExpired)
        message = (
            f"{current_name} 작업 대기 시간을 초과했습니다."
            if timed_out
            else str(error)
        )

        report["status"] = "timed_out" if timed_out else "failed"
        report["termination_reason"] = (
            "deadline_exceeded" if timed_out else "operation_failed"
        )
        report["steps"].append(
            {
                "name": current_name,
                "status": "failed",
                "planned": 1,
                "attempted": 1,
                "completed": 0,
                "error": message,
                "failure": {
                    "operation": current_name.lower(),
                    "path": str(current_path),
                    "errno": error.errno if isinstance(error, OSError) else None,
                    "message": message,
                },
            }
        )
        progress("failed", error=message)

    finally:
        report["finished_at"] = timestamp()

    return report


def main():
    args = parse_args()
    report = run(args)

    print(json.dumps(report, ensure_ascii=False), flush=True)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
