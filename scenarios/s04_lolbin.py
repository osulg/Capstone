"""S04 시스템 Python 작업을 등록하고 실행 결과를 관찰한다."""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

from scenarios.blocked_worker import (
    capture_policy_position,
    find_blocking_event,
    stopped_process_matches,
)
from scenarios.common import (
    emit_progress,
    get_runtime_paths,
    register_process_and_wait,
    timestamp,
)
from scenarios.lolbin_results import is_attack_permission_denied, validate_attack_denial
from scenarios.s01_normal import check_health, find_guardfs_pid
from scenarios.workers import registered_worker

SYSTEM_PYTHON = Path("/usr/bin/python3")
INSTALLED_SCRIPT = Path("/usr/local/bin/holdfs_sim.py")
SOURCE_SCRIPT = (
    Path(__file__).resolve().parents[1] / "experiments/simulators/sim_highentropy.py"
)
FILE_COUNT = 20
TOTAL_TIMEOUT = 150.0


def parse_args():
    mount, underlay = get_runtime_paths()
    parser = argparse.ArgumentParser()
    parser.add_argument("--mount", type=Path, default=mount)
    parser.add_argument("--underlay", type=Path, default=underlay)
    parser.add_argument("--work-dir-name", default="s04_" + uuid.uuid4().hex)
    parser.add_argument("--holdfs-pid", "--guardfs-pid", dest="holdfs_pid", type=int)
    parser.add_argument("--wait-registration-ack", action="store_true")
    args = parser.parse_args()
    if not args.wait_registration_ack:
        parser.error("runner의 등록 응답 통로가 필요합니다.")
    if not re.fullmatch(r"s04_[0-9a-f]{32}", args.work_dir_name):
        parser.error("작업 폴더 이름이 올바르지 않습니다.")
    return args


def run(args):
    mount = Path(os.path.abspath(args.mount.expanduser()))
    underlay = args.underlay.expanduser().resolve()
    workdir = mount / args.work_dir_name
    origin = underlay / args.work_dir_name
    deadline = time.monotonic() + TOTAL_TIMEOUT
    report = {
        "result_version": 2,
        "scenario_id": "S04",
        "pid": os.getpid(),
        "status": "failed",
        "termination_reason": "operation_failed",
        "holdfs_pid": None,
        "started_at": timestamp(),
        "finished_at": None,
        "steps": [],
        "processes": [],
        "task_results": [],
        "attack_started": False,
        "detection_verification": "not_checked",
        "workspace": {"mount_path": str(workdir), "underlay_path": str(origin)},
    }
    current = "PRECHECK"

    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError("전체 실행 제한 시간을 초과했습니다.")
        return value

    def progress(status, **extra):
        emit_progress("S04", {"name": current, "status": status, **extra})

    def complete():
        report["steps"].append(
            {
                "name": current,
                "status": "passed",
                "planned": 1,
                "attempted": 1,
                "completed": 1,
                "failure": None,
            }
        )
        progress("passed")

    def task(action, role, directory):
        limit = min(35.0, remaining())
        command = [
            str(SYSTEM_PYTHON),
            "-u",
            str(INSTALLED_SCRIPT),
            str(directory),
            "--web-action",
            action,
            "--files",
            "20",
            "--size-kb",
            "64",
            "--chunk-kb",
            "16",
            "--duration",
            "30",
            "--delay",
            "0.15",
            "--keep",
        ]
        checkpoint = capture_policy_position() if action == "attack" else None
        with registered_worker(
            "S04",
            role,
            command,
            capture_stdout=True,
            registration_timeout=min(5.0, remaining()),
        ) as (process, metadata):
            report["processes"].append(metadata)
            if action == "attack":
                report["attack_started"] = True
            if process.stdin is not None and process.stdin.closed:
                process.stdin = None
            expires = time.monotonic() + limit
            while True:
                wait = min(expires - time.monotonic(), remaining())
                if wait <= 0:
                    raise subprocess.TimeoutExpired(command, limit)
                try:
                    stdout, _ = process.communicate(timeout=min(0.2, wait))
                    break
                except subprocess.TimeoutExpired:
                    if action != "attack" or not stopped_process_matches(
                        process.pid, metadata.get("start_time_ticks")
                    ):
                        continue
                    # 등록된 시작 tick이 일치하는 자기 자식만 종료·회수한다.
                    event = find_blocking_event(checkpoint, process.pid, origin)
                    process.kill()
                    process.communicate(timeout=3.0)
                    report["worker_outcome"] = {
                        "status": "stopped_reaped",
                        "pid": process.pid,
                        "start_time_ticks": metadata["start_time_ticks"],
                        "returncode": process.returncode,
                        "policy_event": event,
                    }
                    # SIGSTOP만으로 ML 판단이나 원본 보존 성공을 판정하지 않는다.
                    return
            payload = json.loads(stdout.decode("utf-8"))
            if (
                not isinstance(payload, dict)
                or payload.get("action") != action
                or payload.get("pid") != process.pid
            ):
                raise ValueError("작업 결과의 PID 또는 종류가 다릅니다.")
            report["task_results"].append({**payload, "role": role})
            if payload.get("status") == "timed_out":
                raise TimeoutError(payload.get("error") or "작업 시간 초과")
            if (
                action == "attack"
                and process.returncode == 1
                and is_attack_permission_denied(payload)
            ):
                validate_attack_denial(payload)
                # 접근 거부도 관찰 결과다. 사후 파일 확인은 계속 수행한다.
                report["worker_outcome"] = {
                    "status": "permission_denied",
                    "pid": process.pid,
                    "returncode": process.returncode,
                    "failure": payload["failure"],
                }
                return
            if (
                process.returncode != 0
                or payload.get("status") != "passed"
                or not isinstance(payload.get("files"), list)
                or [item.get("name") for item in payload["files"]]
                != [f"file_{i:03d}.txt" for i in range(FILE_COUNT)]
            ):
                raise RuntimeError(
                    payload.get("error") or "작업 결과가 올바르지 않습니다."
                )
            if action == "attack":
                report["worker_outcome"] = {
                    "status": "completed",
                    "pid": process.pid,
                    "returncode": process.returncode,
                }

    try:
        progress("running")
        if sys.platform != "linux":
            raise RuntimeError("Ubuntu에서 실행해야 합니다.")
        holdfs_pid = args.holdfs_pid or find_guardfs_pid()
        check_health(mount, holdfs_pid)
        if not underlay.is_dir() or mount.resolve() == underlay:
            raise ValueError("mount·underlay 경로가 올바르지 않습니다.")
        if not os.access(SYSTEM_PYTHON, os.X_OK):
            raise RuntimeError("시스템 Python을 실행할 수 없습니다.")
        if INSTALLED_SCRIPT.read_bytes() != SOURCE_SCRIPT.read_bytes():
            raise RuntimeError(
                "수정된 원본을 /usr/local/bin/holdfs_sim.py에 다시 복사하세요."
            )
        report["holdfs_pid"] = holdfs_pid
        report["processes"].append(
            register_process_and_wait(
                "S04", "lolbin_manager", timeout_seconds=min(5.0, remaining())
            )
        )
        complete()

        current = "PREPARE"
        progress("running")
        task("prepare", "lolbin_prepare", workdir)
        complete()

        current = "VERIFY_READY"
        progress("running")
        task("verify", "lolbin_verify_mount", workdir)
        task("verify", "lolbin_verify_underlay", origin)
        complete()

        current = "ACTION"
        progress("running")
        task("attack", "lolbin_attack", workdir)
        complete()

        current = "INSPECT"
        progress("running")
        task("inspect", "lolbin_inspect_mount", workdir)
        task("inspect", "lolbin_inspect_underlay", origin)
        complete()
        # 완료는 실행 관찰 완료이며 ML 차단 또는 원본 보존 성공이 아니다.
        report["status"] = "passed"
        report["termination_reason"] = "completed"
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        timed_out = isinstance(error, (TimeoutError, subprocess.TimeoutExpired))
        report["status"] = "timed_out" if timed_out else "failed"
        report["termination_reason"] = (
            "deadline_exceeded" if timed_out else "operation_failed"
        )
        message = str(error) or "S04 실행 실패"
        report["steps"].append(
            {
                "name": current,
                "status": "failed",
                "planned": 1,
                "attempted": 1,
                "completed": 0,
                "error": message,
                "failure": {
                    "operation": current.lower(),
                    "path": str(workdir),
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
