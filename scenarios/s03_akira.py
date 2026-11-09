"""S03 Akira 실행 관리자."""

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

from scenarios.akira_config import (
    ATTACK_TIMEOUT_SECONDS,
    FILE_NAMES,
    PREPARE_TIMEOUT_SECONDS,
    TOTAL_TIMEOUT_SECONDS,
    WORKER_PYTHON,
)
from scenarios.blocked_worker import (
    PolicyBlockedError,
    capture_policy_position,
    communicate_with_policy_watch,
)
from scenarios.common import (
    emit_progress,
    get_runtime_paths,
    register_process_and_wait,
    timestamp,
)
from scenarios.s01_normal import check_health, find_guardfs_pid
from scenarios.workers import registered_worker

SCENARIO_ID = "S03"


def parse_args():
    mount, underlay = get_runtime_paths()
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("head", "tail"), required=True)
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
    parser.add_argument("--worker-python", type=Path, default=WORKER_PYTHON)
    parser.add_argument(
        "--total-timeout",
        type=float,
        default=TOTAL_TIMEOUT_SECONDS,
    )
    parser.add_argument("--wait-registration-ack", action="store_true")
    args = parser.parse_args()

    if not args.wait_registration_ack:
        parser.error("runner의 등록 응답 통로가 필요합니다.")

    if not re.fullmatch(r"s03_[0-9a-f]{32}", args.work_dir_name):
        parser.error("작업 폴더 이름이 올바르지 않습니다.")

    if not math.isfinite(args.total_timeout) or args.total_timeout <= 0:
        parser.error("전체 제한 시간은 유한한 양수여야 합니다.")

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
    holdfs_pid = args.holdfs_pid

    report = {
        "result_version": 2,
        "scenario_id": SCENARIO_ID,
        "mode": args.mode,
        "pid": os.getpid(),
        "holdfs_pid": None,
        "status": "failed",
        "termination_reason": "operation_failed",
        "started_at": timestamp(),
        "finished_at": None,
        "attack_started": False,
        "processes": [],
        "steps": [],
        "task_results": [],
        "workspace": {
            "mount_path": str(workdir),
            "underlay_path": str(underlay_workdir),
        },
        "detection_verification": "not_checked",
    }

    current_name = "PRECHECK"
    current_path = mount

    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError("전체 실행 제한 시간을 초과했습니다.")
        return value

    def progress(status, **details):
        emit_progress(
            SCENARIO_ID,
            {"name": current_name, "status": status, **details},
        )

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
        limit = min(
            ATTACK_TIMEOUT_SECONDS if action == "attack" else PREPARE_TIMEOUT_SECONDS,
            remaining(),
        )
        command = [
            str(worker_python),
            "-u",
            "-m",
            "scenarios.akira_tasks",
            action,
            "--root",
            str(directory),
            "--mode",
            args.mode,
            "--timeout",
            str(limit),
        ]

        checkpoint = capture_policy_position() if action == "attack" else None

        with registered_worker(
            SCENARIO_ID,
            role,
            command,
            registration_timeout=min(5.0, remaining()),
            capture_stdout=True,
        ) as (process, metadata):
            report["processes"].append(metadata)

            if action == "attack":
                report["attack_started"] = True

            if process.stdin is not None and process.stdin.closed:
                process.stdin = None

            if action == "attack":
                try:
                    stdout, _ = communicate_with_policy_watch(
                        process,
                        metadata,
                        timeout=min(limit + 1.0, remaining()),
                        checkpoint=checkpoint,
                        workspace=underlay_workdir,
                    )
                except PolicyBlockedError as error:
                    report["policy_block"] = error.evidence
                    raise
            else:
                stdout, _ = process.communicate(
                    timeout=min(limit + 1.0, remaining()),
                )

            payload = json.loads(stdout.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("자식 결과가 객체가 아닙니다.")

            if payload.get("action") != action or payload.get("mode") != args.mode:
                raise ValueError("자식 작업 종류 또는 모드가 다릅니다.")

            planned = len(FILE_NAMES) * 3 + 1 if action == "attack" else len(FILE_NAMES)
            counts = [payload.get(key) for key in ("planned", "attempted", "completed")]

            if any(type(value) is not int for value in counts):
                raise ValueError("자식 작업 수가 올바르지 않습니다.")

            if not (counts[0] == planned and 0 <= counts[2] <= counts[1] <= planned):
                raise ValueError("자식 작업 집계가 일치하지 않습니다.")

            operations = payload.get("operations")
            if not isinstance(operations, list) or len(operations) != counts[2]:
                raise ValueError("자식 작업 기록 수가 다릅니다.")

            status = payload.get("status")
            if status not in ("passed", "failed", "timed_out"):
                raise ValueError("자식 작업 상태가 올바르지 않습니다.")

            if status == "passed":
                if (
                    counts[1] != planned
                    or counts[2] != planned
                    or payload.get("failure") is not None
                    or process.returncode != 0
                ):
                    raise ValueError("자식 완료 결과가 일치하지 않습니다.")
            elif not isinstance(payload.get("failure"), dict):
                raise ValueError("자식 실패 원인이 없습니다.")

            report["task_results"].append(
                {
                    **payload,
                    "role": role,
                    "pid": metadata["pid"],
                }
            )

            if status == "timed_out":
                raise TimeoutError(f"{role} 작업 시간이 초과됐습니다.")

            if status != "passed":
                raise RuntimeError(
                    f"{role}: {payload['failure'].get('message', '작업 실패')}"
                )

        check_health(mount, holdfs_pid)

    try:
        progress("running")

        if sys.platform != "linux":
            raise RuntimeError("Linux에서 실행해야 합니다.")

        if args.mode not in ("head", "tail"):
            raise ValueError("지원하지 않는 Akira 모드입니다.")

        if holdfs_pid is None:
            holdfs_pid = find_guardfs_pid()

        check_health(mount, holdfs_pid)

        if not underlay.is_dir() or mount.resolve() == underlay:
            raise ValueError("mount·underlay 경로가 올바르지 않습니다.")

        if not worker_python.is_file() or not os.access(worker_python, os.X_OK):
            raise RuntimeError("작업 Python을 실행할 수 없습니다.")

        report["holdfs_pid"] = holdfs_pid
        report["processes"].append(
            register_process_and_wait(
                SCENARIO_ID,
                "akira_manager",
                timeout_seconds=min(5.0, remaining()),
            )
        )
        complete()

        current_name = "PREPARE"
        current_path = workdir
        progress("running")
        workdir.mkdir(exist_ok=False)
        run_task("prepare", "akira_prepare", workdir)
        complete()

        current_name = "VERIFY_READY"
        progress("running")
        run_task("verify", "akira_verify_mount", workdir)
        run_task("verify", "akira_verify_underlay", underlay_workdir)
        complete()

        current_name = "ACTION"
        progress("running")
        run_task("attack", "akira_attack", workdir)
        complete()

        # 공격이 끝난 뒤 별도 PID로 관찰한다.
        current_name = "INSPECT"
        progress("running")
        run_task("inspect", "akira_inspect_mount", workdir)
        current_path = underlay_workdir
        run_task("inspect", "akira_inspect_underlay", underlay_workdir)
        complete()

        # 전체 실행 완료이며 보호 성공을 뜻하지 않는다.
        report["status"] = "passed"
        report["termination_reason"] = "completed"

    except (
        OSError,
        ValueError,
        RuntimeError,
        subprocess.TimeoutExpired,
    ) as error:
        timed_out = isinstance(error, (TimeoutError, subprocess.TimeoutExpired))
        message = str(error) or "Akira 실행 실패"
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
                    "errno": getattr(error, "errno", None),
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
