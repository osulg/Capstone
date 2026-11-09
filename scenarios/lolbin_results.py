"""S04 관찰 결과와 등록된 작업 PID의 연결을 검증한다."""


def is_attack_permission_denied(task):
    """접근 거부를 관찰하되 정책 차단 또는 ML 판정이라고 단정하지 않는다."""
    failure = task.get("failure")
    return (
        task.get("action") == "attack"
        and task.get("status") == "failed"
        and isinstance(failure, dict)
        and type(failure.get("errno")) is int
        and failure["errno"] in (1, 13)
        and failure.get("operation") in ("read_overwrite", "rename")
        and isinstance(task.get("error"), str)
        and bool(task["error"])
    )


def validate_attack_denial(task):
    files = task.get("files")
    if (
        not is_attack_permission_denied(task)
        or not isinstance(files, list)
        or len(files) >= 20
        or any(not isinstance(item, dict) for item in files)
        or [item.get("name") for item in files]
        != [f"file_{index:03d}.txt" for index in range(len(files))]
    ):
        raise ValueError("S04 접근 거부 작업 기록이 올바르지 않습니다.")


def validate_lolbin_success(result, record):
    if result.get("result_version") != 2 or result.get("attack_started") is not True:
        raise ValueError("S04 공격 시작 또는 결과 버전이 올바르지 않습니다.")
    registered = {(item.role, item.pid): item for item in record.processes}
    outcome = result.get("worker_outcome")
    if not isinstance(outcome, dict):
        raise ValueError("S04 공격 프로세스 결과가 없습니다.")
    attack = registered.get(("lolbin_attack", outcome.get("pid")))
    if attack is None:
        raise ValueError("S04 공격 PID가 등록되지 않았습니다.")
    stopped = outcome.get("status") == "stopped_reaped"
    denied = outcome.get("status") == "permission_denied"
    if stopped:
        if (
            outcome.get("returncode") != -9
            or outcome.get("start_time_ticks") != attack.start_time_ticks
        ):
            raise ValueError("정지 프로세스 회수 근거가 일치하지 않습니다.")
    elif denied:
        if outcome.get("returncode") != 1:
            raise ValueError("S04 접근 거부 종료 코드가 일치하지 않습니다.")
    elif outcome.get("status") != "completed" or outcome.get("returncode") != 0:
        raise ValueError("S04 공격 종료 상태가 올바르지 않습니다.")
    expected = [
        ("lolbin_prepare", "prepare"),
        ("lolbin_verify_mount", "verify"),
        ("lolbin_verify_underlay", "verify"),
    ]
    if not stopped:
        expected.append(("lolbin_attack", "attack"))
    expected.extend(
        [("lolbin_inspect_mount", "inspect"), ("lolbin_inspect_underlay", "inspect")]
    )
    tasks = result.get("task_results")
    if not isinstance(tasks, list) or any(not isinstance(task, dict) for task in tasks):
        raise ValueError("S04 작업 결과 목록이 올바르지 않습니다.")
    if [(task.get("role"), task.get("action")) for task in tasks] != expected:
        raise ValueError("S04 작업 순서가 일치하지 않습니다.")
    names = [f"file_{index:03d}.txt" for index in range(20)]
    for task in tasks:
        if (task.get("role"), task.get("pid")) not in registered:
            raise ValueError("S04 작업 PID 등록 근거가 없습니다.")
        if denied and task["action"] == "attack":
            validate_attack_denial(task)
            if task["failure"] != outcome.get("failure") or task["pid"] != attack.pid:
                raise ValueError("S04 접근 거부 근거가 일치하지 않습니다.")
            continue
        if task.get("status") != "passed" or task.get("error") is not None:
            raise ValueError("S04 작업 완료 또는 PID 등록 근거가 없습니다.")
        files = task.get("files")
        if (
            not isinstance(files, list)
            or any(not isinstance(item, dict) for item in files)
            or [item.get("name") for item in files] != names
        ):
            raise ValueError("S04 파일 목록이 일치하지 않습니다.")
        if task["action"] == "inspect":
            for item in files:
                if any(
                    item.get(key) not in ("matched", "changed", "missing")
                    for key in ("original", "renamed")
                ):
                    raise ValueError("S04 파일 관찰 상태가 올바르지 않습니다.")
