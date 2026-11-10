"""Huntress 로그 삭제 완료 결과의 신원·경로·집계 검증."""

from pathlib import Path

from scenarios.huntress_config import DELETE_FILES


def validate_delete_success(result, record):
    if record.workspace is None:
        raise ValueError("실행 작업 경로가 없습니다.")

    mount = Path(record.workspace.mount_path)
    underlay = Path(record.workspace.underlay_path)

    definitions = (
        ("huntress_delete_prepare", "prepare", mount),
        ("huntress_delete_verify_mount", "verify", mount),
        ("huntress_delete_verify_underlay", "verify", underlay),
        ("huntress_delete", "delete", mount),
        ("huntress_delete_inspect_mount", "inspect", mount),
        ("huntress_delete_inspect_underlay", "inspect", underlay),
    )

    tasks = result.get("task_results")
    if not isinstance(tasks, list) or len(tasks) != len(definitions):
        raise ValueError("삭제 작업 결과 수가 일치하지 않습니다.")

    registered = {
        (process.role, process.pid)
        for process in record.processes
        if process.start_time_ticks is not None
    }

    allowed_values = {
        "prepare": ("created",),
        "verify": ("matched",),
        "delete": (
            "unlink_succeeded",
            "permission_denied",
            "missing",
            "delete_error",
        ),
        "inspect": ("matched", "changed", "missing", "unreadable"),
    }

    for task, (role, action, root) in zip(tasks, definitions):
        if not isinstance(task, dict):
            raise ValueError("작업 결과가 객체가 아닙니다.")

        if task.get("role") != role or task.get("action") != action:
            raise ValueError("삭제 작업 순서가 일치하지 않습니다.")

        pid = task.get("pid")
        if type(pid) is not int or (role, pid) not in registered:
            raise ValueError("등록되지 않은 삭제 작업 PID입니다.")

        if task.get("status") != "passed" or task.get("failure") is not None:
            raise ValueError("완료되지 않은 삭제 작업이 있습니다.")

        for key in ("planned", "attempted", "completed"):
            value = task.get(key)
            if type(value) is not int or value != len(DELETE_FILES):
                raise ValueError("삭제 작업 집계가 일치하지 않습니다.")

        operations = task.get("operations")
        if not isinstance(operations, list) or len(operations) != len(DELETE_FILES):
            raise ValueError("삭제 작업 기록 수가 일치하지 않습니다.")

        for name, item in zip(DELETE_FILES, operations):
            if not isinstance(item, dict):
                raise ValueError("파일 작업 기록이 객체가 아닙니다.")

            if item.get("name") != name or item.get("path") != str(root / name):
                raise ValueError("파일 순서 또는 경로가 일치하지 않습니다.")

            field = "state" if action == "inspect" else "outcome"
            if item.get(field) not in allowed_values[action]:
                raise ValueError("파일 관찰 결과가 올바르지 않습니다.")

    observation = result.get("delete_observation")
    if not isinstance(observation, dict):
        raise ValueError("삭제 관찰 정보가 없습니다.")

    if (
        observation.get("delete_started") is not True
        or observation.get("policy_verification") != "not_checked"
    ):
        raise ValueError("삭제 시작 정보 또는 정책 검증 상태가 올바르지 않습니다.")

    deletion = tasks[3]["operations"]
    expected_counts = {
        "unlink_succeeded": sum(
            item["outcome"] == "unlink_succeeded" for item in deletion
        ),
        "permission_denied": sum(
            item["outcome"] == "permission_denied" for item in deletion
        ),
    }

    for key, expected in expected_counts.items():
        actual = observation.get(key)
        if type(actual) is not int or actual != expected:
            raise ValueError("삭제 관찰 요약 수가 일치하지 않습니다.")

    expected_files = [
        {
            "name": name,
            "mount": mount_item["state"],
            "underlay": underlay_item["state"],
        }
        for name, mount_item, underlay_item in zip(
            DELETE_FILES,
            tasks[4]["operations"],
            tasks[5]["operations"],
        )
    ]

    if observation.get("files") != expected_files:
        raise ValueError("사후 파일 상태와 요약 결과가 일치하지 않습니다.")
