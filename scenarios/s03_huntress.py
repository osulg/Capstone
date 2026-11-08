"""S03 Huntress 일반 읽기 관리자.

등록 응답을 제공하는 runner에서 실행한다.
일반 읽기만 지원하며 허니팟·삭제 모드는 아직 실행하지 않는다.
"""

import argparse
import json
import math
import os
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

from scenarios.common import (
    emit_progress,
    get_runtime_paths,
    register_process_and_wait,
    timestamp,
)
from scenarios.huntress_config import (
    PREPARE_TIMEOUT_SECONDS,
    READ_FILES,
    TOTAL_TIMEOUT_SECONDS,
    WORKER_PYTHON,
)
from scenarios.results import validate_result_details
from scenarios.s01_normal import check_health, find_guardfs_pid
from scenarios.workers import registered_worker

SCENARIO_ID = "S03"


def validate_task_result(payload, action, returncode):
    """자식 결과의 작업 종류·집계·종료 상태를 검사한다."""
    if not isinstance(payload, dict):
        raise ValueError("자식 결과가 JSON 객체가 아닙니다.")

    if payload.get("action") != action:
        raise ValueError("자식 작업 종류가 일치하지 않습니다.")

    status = payload.get("status")
    reasons = {
        "passed": "completed",
        "failed": "operation_failed",
        "timed_out": "deadline_exceeded",
    }

    if not isinstance(status, str) or status not in reasons:
        raise ValueError("잘못된 자식 결과 상태입니다.")

    if type(returncode) is not int:
        raise ValueError("자식 종료 코드를 확인하지 못했습니다.")

    if (returncode == 0) != (status == "passed"):
        raise ValueError("자식 종료 코드와 결과가 일치하지 않습니다.")

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

    if payload["planned"] != len(READ_FILES):
        raise ValueError("예정 파일 수가 일치하지 않습니다.")

    operations = payload.get("operations")
    if not isinstance(operations, list):
        raise ValueError("파일별 작업 결과가 없습니다.")

    if any(not isinstance(item, dict) for item in operations):
        raise ValueError("잘못된 파일별 작업 결과입니다.")

    names = [item.get("name") for item in operations]
    if names != list(READ_FILES)[: len(names)]:
        raise ValueError("파일별 작업 순서가 일치하지 않습니다.")

    if any(item.get("status") not in ("passed", "failed") for item in operations):
        raise ValueError("잘못된 파일별 작업 상태입니다.")

    successful = [item for item in operations if item["status"] == "passed"]
    if len(successful) != payload["completed"]:
        raise ValueError("파일별 성공 수와 완료 수가 다릅니다.")

    if status == "passed":
        if names != list(READ_FILES):
            raise ValueError("성공 결과에 누락된 파일이 있습니다.")

        if action in ("verify", "read"):
            if any(item.get("content_matched") is not True for item in successful):
                raise ValueError("예상 내용과 다른 파일이 있습니다.")

    return payload


def parse_args():
    mount, underlay = get_runtime_paths()

    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("read",), required=True)
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
        default=f"s03_{uuid.uuid4().hex}",
    )
    parser.add_argument(
        "--worker-python",
        type=Path,
        default=WORKER_PYTHON,
    )
    parser.add_argument(
        "--prepare-timeout",
        type=float,
        default=PREPARE_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--total-timeout",
        type=float,
        default=TOTAL_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--wait-registration-ack",
        action="store_true",
    )
    args = parser.parse_args()

    if not args.wait_registration_ack:
        parser.error("runner의 등록 응답 통로가 필요합니다.")

    if re.fullmatch(r"s03_[0-9a-f]{32}", args.work_dir_name) is None:
        parser.error("작업 폴더 이름은 s03_ 뒤에 16진수 32자리입니다.")

    for value in (args.prepare_timeout, args.total_timeout):
        if not math.isfinite(value) or value <= 0:
            parser.error("제한 시간은 유한한 양수여야 합니다.")

    if args.holdfs_pid is not None and args.holdfs_pid <= 0:
        parser.error("HoldFS PID는 양수여야 합니다.")

    return args


def run(args):
    mount = Path(os.path.abspath(args.mount.expanduser()))
    underlay = args.underlay.expanduser().resolve()
    worker_python = args.worker_python.expanduser().absolute()
    workdir = mount / args.work_dir_name
    underlay_workdir = underlay / args.work_dir_name
    deadline = time.monotonic() + args.total_timeout

    report = {
        "result_version": 2,
        "scenario_id": SCENARIO_ID,
        "mode": "read",
        "pid": os.getpid(),
        "holdfs_pid": None,
        "status": "failed",
        "termination_reason": "operation_failed",
        "started_at": timestamp(),
        "finished_at": None,
        "processes": [],
        "steps": [],
        "task_results": [],
        "workspace": {
            "mount_path": str(workdir),
            "underlay_path": str(underlay_workdir),
        },
        "content_verification": {
            "status": "not_checked",
        },
        "detection_verification": "not_checked",
        "execution_settings": {
            "worker_python": str(worker_python),
            "files": len(READ_FILES),
            "read_passes": 1,
            "delay_seconds": 0.1,
            "total_timeout_seconds": args.total_timeout,
        },
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

    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError("전체 작업 제한 시간을 초과했습니다.")
        return value

    def complete():
        report["steps"].append(
            {
                "name": current_name,
                "status": "passed",
                "planned": 1,
                "attempted": 1,
                "completed": 1,
                "failure": None,
            }
        )
        progress("passed")

    def run_task(action, role, directory):
        limit = min(args.prepare_timeout, remaining())
        command = [
            str(worker_python),
            "-u",
            "-m",
            "scenarios.huntress_tasks",
            action,
            "--workdir",
            str(directory),
            "--timeout",
            str(limit),
        ]

        with registered_worker(
            SCENARIO_ID,
            role,
            command,
            registration_timeout=min(5.0, remaining()),
            capture_stdout=True,
        ) as (process, metadata):
            report["processes"].append(metadata)

            if process.stdin is not None and process.stdin.closed:
                process.stdin = None

            stdout, _ = process.communicate(
                timeout=min(limit + 1.0, remaining()),
            )

            try:
                payload = json.loads(stdout.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as error:
                raise RuntimeError(
                    f"{role}의 JSON 결과가 올바르지 않습니다."
                ) from error

            # 검증을 통과하지 않은 JSON을 정상 작업 결과에 섞지 않는다.
            try:
                payload = validate_task_result(payload, action, process.returncode)
            except ValueError as error:
                raise RuntimeError(f"{role} 결과 검증 실패: {error}") from error

            report["task_results"].append(
                {
                    "role": role,
                    "pid": metadata["pid"],
                    **payload,
                }
            )

            if payload["status"] == "timed_out":
                raise TimeoutError(f"{role} 제한 시간을 초과했습니다.")

            if payload["status"] != "passed":
                raise RuntimeError(f"{role} 실패: {payload['failure']['message']}")

        # context 종료 시 해당 자식의 종료·회수를 마친 상태다.
        check_health(mount, holdfs_pid)

    try:
        progress("running")

        if sys.platform != "linux":
            raise RuntimeError("Linux에서 실행해야 합니다.")

        if args.mode != "read":
            raise RuntimeError("현재는 일반 읽기 모드만 지원합니다.")

        if holdfs_pid is None:
            holdfs_pid = find_guardfs_pid()

        check_health(mount, holdfs_pid)

        if not underlay.is_dir():
            raise RuntimeError("underlay 디렉터리가 없습니다.")

        if mount.resolve() == underlay:
            raise RuntimeError("mount와 underlay가 같을 수 없습니다.")

        if not worker_python.is_file() or not os.access(worker_python, os.X_OK):
            raise RuntimeError(f"작업 Python을 실행할 수 없습니다: {worker_python}")

        report["holdfs_pid"] = holdfs_pid
        report["processes"].append(
            register_process_and_wait(
                SCENARIO_ID,
                "huntress_manager",
                timeout_seconds=min(5.0, remaining()),
            )
        )
        complete()

        current_name = "PREPARE"
        current_path = workdir
        progress("running")
        workdir.mkdir(exist_ok=False)
        run_task("prepare", "huntress_prepare", workdir)
        complete()

        current_name = "VERIFY_READY"
        progress("running")
        run_task("verify", "huntress_verify_ready", workdir)
        complete()

        current_name = "READ"
        progress("running")
        run_task("read", "huntress_read", workdir)
        complete()

        # 읽기 자식이 종료된 이후 별도 PID로 내용을 확인한다.
        current_name = "VERIFY_MOUNT"
        progress("running")
        run_task("verify", "huntress_verify_mount", workdir)
        complete()

        current_name = "VERIFY_UNDERLAY"
        current_path = underlay_workdir
        progress("running")
        run_task(
            "verify",
            "huntress_verify_underlay",
            underlay_workdir,
        )
        complete()

        report["content_verification"] = {
            "status": "passed",
            "files": len(READ_FILES),
            "observed_at": timestamp(),
            "scope": "관찰 시점의 mount·underlay 더미 파일 내용",
        }
        report["status"] = "passed"
        report["termination_reason"] = "completed"

    except (
        OSError,
        RuntimeError,
        subprocess.TimeoutExpired,
    ) as error:
        timed_out = isinstance(error, (TimeoutError, subprocess.TimeoutExpired))
        message = str(error) or "작업을 완료하지 못했습니다."

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
                    "errno": (error.errno if isinstance(error, OSError) else None),
                    "message": message,
                },
            }
        )
        progress("failed", error=message)

    finally:
        report["finished_at"] = timestamp()

    return report


def main():
    report = run(parse_args())
    print(json.dumps(report, ensure_ascii=False), flush=True)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
