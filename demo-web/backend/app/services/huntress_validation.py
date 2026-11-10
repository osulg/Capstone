"""Huntress 허니팟 관리자 결과의 신원·순서·경로 검증."""

from pathlib import Path

from scenarios.huntress_config import HONEYPOT_FILES
from scenarios.huntress_honeypot_tasks import honeypot_paths
from scenarios.s02_huntress import validate_honeypot_result


def validate_honeypot_success(result, record):
    """관찰 완료 결과를 검사하며 정책 차단 여부는 판정하지 않는다."""
    if record.workspace is None:
        raise ValueError("실행 작업 경로가 없습니다.")

    observation = result.get("honeypot_observation")
    if not isinstance(observation, dict):
        raise ValueError("허니팟 관찰 정보가 없습니다.")

    if observation.get("access_started") is not True:
        raise ValueError("허니팟 접근 시작을 확인하지 못했습니다.")

    if observation.get("policy_verification") != "not_checked":
        raise ValueError("관리자가 정책 차단을 임의로 판정했습니다.")

    # 자식이 보고한 경로를 신뢰하지 않고 runner의 경로에서 계산한다.
    mount = Path(record.workspace.mount_path).parent
    underlay = Path(record.workspace.underlay_path).parent
    mount_root, underlay_root = honeypot_paths(mount, underlay)

    if observation.get("mount_root") != str(mount_root) or observation.get(
        "underlay_root"
    ) != str(underlay_root):
        raise ValueError("허니팟 관찰 경로가 일치하지 않습니다.")

    expected_targets = [
        {
            "name": name,
            "mount_path": str(mount_root / name),
            "underlay_path": str(underlay_root / name),
        }
        for name in HONEYPOT_FILES
    ]

    if observation.get("targets") != expected_targets:
        raise ValueError("허니팟 미끼 목록이 일치하지 않습니다.")

    tasks = result.get("task_results")
    if not isinstance(tasks, list):
        raise ValueError("허니팟 자식 작업 결과가 없습니다.")

    if any(not isinstance(task, dict) for task in tasks):
        raise ValueError("잘못된 허니팟 자식 결과입니다.")

    expected_tasks = [
        ("huntress_honeypot_check", "check"),
        ("huntress_honeypot_access", "access"),
    ]

    actual_tasks = [(task.get("role"), task.get("action")) for task in tasks]

    if actual_tasks != expected_tasks:
        raise ValueError("허니팟 작업 순서가 일치하지 않습니다.")

    registered = {
        (process.role, process.pid)
        for process in record.processes
        if process.start_time_ticks is not None
    }

    for task in tasks:
        if task.get("status") != "passed":
            raise ValueError("완료되지 않은 허니팟 작업이 있습니다.")

        if (
            type(task.get("pid")) is not int
            or (task.get("role"), task["pid"]) not in registered
        ):
            raise ValueError("등록되지 않은 허니팟 자식 결과입니다.")

        validate_honeypot_result(
            task,
            task["action"],
            returncode=0,
        )

        expected_root = underlay_root if task["action"] == "check" else mount_root

        for operation in task["operations"]:
            expected_path = expected_root / operation["name"]

            if operation.get("path") != str(expected_path):
                raise ValueError("허니팟 작업 대상 경로가 다릅니다.")
