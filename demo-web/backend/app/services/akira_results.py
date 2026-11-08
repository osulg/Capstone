"""Akira 완료 결과 검증과 종료 후 파일 상태 조회."""

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from scenarios.akira_config import FILE_NAMES, NEW_EXT, NOTE_NAME

PROJECT_ROOT = Path(__file__).resolve().parents[4]
FILE_STATES = {"matched", "changed", "missing", "unreadable"}


def validate_task(task, action, mode, root):
    if not isinstance(task, dict):
        raise ValueError("Akira 작업 결과가 객체가 아닙니다.")

    if (
        task.get("action") != action
        or task.get("mode") != mode
        or task.get("status") != "passed"
        or task.get("failure") is not None
    ):
        raise ValueError("Akira 작업 완료 정보가 올바르지 않습니다.")

    expected = []
    for name in FILE_NAMES:
        path = str(root / name)

        if action == "attack":
            expected.extend(
                [
                    ("read", path),
                    ("overwrite", path),
                    ("rename", path),
                ]
            )
        else:
            operation = {
                "prepare": "create",
                "verify": "verify",
                "inspect": "inspect",
            }[action]
            expected.append((operation, path))

    if action == "attack":
        expected.append(("note", str(root / NOTE_NAME)))

    for key in ("planned", "attempted", "completed"):
        value = task.get(key)
        if type(value) is not int or value != len(expected):
            raise ValueError("Akira 작업 수가 일치하지 않습니다.")

    operations = task.get("operations")
    if not isinstance(operations, list) or any(
        not isinstance(item, dict) for item in operations
    ):
        raise ValueError("Akira 작업 기록이 올바르지 않습니다.")

    if [(item.get("operation"), item.get("path")) for item in operations] != expected:
        raise ValueError("Akira 작업 순서 또는 경로가 다릅니다.")

    for item in operations:
        if action == "verify" and item.get("state") != "matched":
            raise ValueError("준비 파일의 내용이 일치하지 않습니다.")

        if action == "inspect" and (
            item.get("original") not in FILE_STATES
            or item.get("renamed") not in FILE_STATES
        ):
            raise ValueError("파일 관찰 상태가 올바르지 않습니다.")

        if item["operation"] == "rename":
            if item.get("new_path") != item["path"] + NEW_EXT:
                raise ValueError("변경된 파일 경로가 다릅니다.")

    return operations


def validate_akira_success(result, record):
    if record.workspace is None:
        raise ValueError("Akira 실행 경로가 없습니다.")

    if result.get("attack_started") is not True:
        raise ValueError("Akira 공격 시작 정보가 없습니다.")

    mount = Path(record.workspace.mount_path)
    underlay = Path(record.workspace.underlay_path)

    definitions = (
        ("akira_prepare", "prepare", mount),
        ("akira_verify_mount", "verify", mount),
        ("akira_verify_underlay", "verify", underlay),
        ("akira_attack", "attack", mount),
        ("akira_inspect_mount", "inspect", mount),
        ("akira_inspect_underlay", "inspect", underlay),
    )

    tasks = result.get("task_results")
    if not isinstance(tasks, list) or len(tasks) != len(definitions):
        raise ValueError("Akira 자식 작업 수가 다릅니다.")

    registered = {
        (process.role, process.pid)
        for process in record.processes
        if process.start_time_ticks is not None
    }

    for task, (role, action, root) in zip(tasks, definitions):
        if not isinstance(task, dict):
            raise ValueError("Akira 자식 결과가 객체가 아닙니다.")

        pid = task.get("pid")
        if (
            task.get("role") != role
            or type(pid) is not int
            or (role, pid) not in registered
        ):
            raise ValueError("Akira 자식 작업 순서 또는 등록 PID가 다릅니다.")

        validate_task(task, action, record.mode, root)


def observe_akira_files(record, *, cleanup_confirmed):
    result = {
        "status": "unknown",
        "observed_at": None,
        "cleanup_confirmed": cleanup_confirmed,
        "files": [],
        "issues": [],
    }

    workspace = record.workspace
    if (
        not cleanup_confirmed
        or record.scenario_id != "S04"
        or record.mode not in ("head", "tail")
        or workspace is None
        or workspace.name != f"s04_{record.run_id}"
    ):
        result["issues"].append("실행 경로 또는 프로세스 정리를 확인하지 못했습니다.")
        return result

    observations = {}

    for side, root in (
        ("mount", workspace.mount_path),
        ("underlay", workspace.underlay_path),
    ):
        try:
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "scenarios.akira_tasks",
                    "inspect",
                    "--root",
                    root,
                    "--mode",
                    record.mode,
                    "--timeout",
                    "5",
                ],
                cwd=PROJECT_ROOT,
                capture_output=True,
                timeout=7,
                check=True,
            )
            payload = json.loads(completed.stdout.decode("utf-8"))
            observations[side] = validate_task(
                payload,
                "inspect",
                record.mode,
                Path(root),
            )
        except (
            OSError,
            ValueError,
            UnicodeDecodeError,
            subprocess.SubprocessError,
        ) as error:
            result["issues"].append(
                f"{side} 상태 조회 실패: {type(error).__name__}: {error}"
            )

    for index, name in enumerate(FILE_NAMES):
        item = {"name": name}

        for side in ("mount", "underlay"):
            operations = observations.get(side)
            item[side] = (
                {
                    "original": operations[index]["original"],
                    "renamed": operations[index]["renamed"],
                }
                if operations is not None
                else {"original": "unreadable", "renamed": "unreadable"}
            )

        result["files"].append(item)

    if not result["issues"] and all(
        item[side][kind] != "unreadable"
        for item in result["files"]
        for side in ("mount", "underlay")
        for kind in ("original", "renamed")
    ):
        result["status"] = "observed"

    result["observed_at"] = datetime.now(UTC).isoformat()
    return result


def verify_akira_protection(record):
    result = {
        "status": "unknown",
        "reason": "Akira 보호 검증에 필요한 근거가 부족합니다.",
        "observed_at": datetime.now(UTC).isoformat(),
        "files": [],
        "blocking_events": [],
        "scope": "이번 실행의 공격 차단과 원본 VM 더미 파일 보존",
    }

    if (
        record.scenario_id != "S04"
        or record.mode not in ("head", "tail")
        or record.status == "cancelled"
        or record.workspace is None
    ):
        return result

    payload = record.result
    if not isinstance(payload, dict) or payload.get("attack_started") is not True:
        return result

    attackers = [
        process
        for process in record.processes
        if process.role == "akira_attack" and process.start_time_ticks is not None
    ]
    if len(attackers) != 1:
        return result

    attacker = attackers[0]
    block = payload.get("policy_block")
    if (
        not isinstance(block, dict)
        or block.get("confirmed") is not True
        or block.get("process_reaped") is not True
        or block.get("pid") != attacker.pid
        or block.get("start_time_ticks") != attacker.start_time_ticks
    ):
        result["reason"] = "등록된 공격 PID의 차단·회수를 확인하지 못했습니다."
        return result

    # 준비와 공개 확인이 끝난 실행인지 먼저 검사한다.
    tasks = payload.get("task_results")
    if not isinstance(tasks, list) or len(tasks) < 3:
        return result

    mount = Path(record.workspace.mount_path)
    underlay = Path(record.workspace.underlay_path)
    registered = {
        (process.role, process.pid)
        for process in record.processes
        if process.start_time_ticks is not None
    }

    definitions = (
        ("akira_prepare", "prepare", mount),
        ("akira_verify_mount", "verify", mount),
        ("akira_verify_underlay", "verify", underlay),
    )

    try:
        for task, (role, action, root) in zip(tasks[:3], definitions):
            if (
                not isinstance(task, dict)
                or task.get("role") != role
                or type(task.get("pid")) is not int
                or (role, task["pid"]) not in registered
            ):
                raise ValueError("준비 작업의 등록 PID 또는 순서가 다릅니다.")

            validate_task(task, action, record.mode, root)
    except ValueError as error:
        result["reason"] = f"공격 전 준비 결과를 검증하지 못했습니다: {error}"
        return result

    observation = record.akira_observation
    if (
        not isinstance(observation, dict)
        or observation.get("cleanup_confirmed") is not True
        or observation.get("status") != "observed"
        or observation.get("issues")
    ):
        result["reason"] = "프로세스 정리 이후 파일 상태를 모두 확인하지 못했습니다."
        return result

    files = observation.get("files")
    if (
        not isinstance(files, list)
        or any(not isinstance(item, dict) for item in files)
        or [item.get("name") for item in files] != list(FILE_NAMES)
    ):
        result["reason"] = "원본 파일 확인 목록이 일치하지 않습니다."
        return result

    result["files"] = files

    for item in files:
        for side in ("mount", "underlay"):
            state = item.get(side)
            if not isinstance(state, dict):
                return result

            if state.get("original") in ("changed", "missing") or state.get(
                "renamed"
            ) in ("matched", "changed"):
                result.update(
                    status="failed",
                    reason="일부 원본의 변경·누락 또는 이름 변경 파일을 확인했습니다.",
                )
                return result

            if state.get("original") != "matched" or state.get("renamed") != "missing":
                result["reason"] = "일부 파일의 원본 보존 상태를 확정하지 못했습니다."
                return result

    # 독립적으로 수집한 이번 실행의 정책 로그와 대조한다.
    collection = record.event_collection
    if collection is None:
        return result

    original_paths = {str(underlay / name) for name in FILE_NAMES}
    rename_paths = {
        f"{underlay / name} -> {underlay / (name + NEW_EXT)}" for name in FILE_NAMES
    }

    for event in collection.events:
        if (
            event.get("source") != "policy"
            or event.get("pid") != attacker.pid
            or event.get("level") != "HIGH"
            or event.get("result") != "BLOCKED"
        ):
            continue

        operation = event.get("op")
        path = event.get("path")

        if (operation in ("WRITE", "TRUNCATE") and path in original_paths) or (
            operation == "RENAME" and path in rename_paths
        ):
            result["blocking_events"].append(event)

    if not result["blocking_events"]:
        result["reason"] = (
            "원본은 일치하지만 수집 로그에서 공격 차단 근거를 확인하지 못했습니다."
        )
        return result

    if collection.issues or collection.pending_record:
        result["reason"] = "원본과 차단 근거는 있으나 로그 수집이 불완전합니다."
        return result

    result.update(
        status="passed",
        reason=(
            f"공격 차단과 프로세스 회수, "
            f"mount·underlay 원본 {len(FILE_NAMES)}개 내용 일치를 확인했습니다."
        ),
    )
    return result
