"""시나리오 결과 형식 검증."""


def validate_result_details(result: dict) -> None:
    """기존 결과는 유지하고 버전 2의 상세 결과를 검사한다."""
    version = result.get("result_version", 1)

    if type(version) is not int or version not in (1, 2):
        raise ValueError("지원하지 않는 결과 버전입니다.")

    if version == 1:
        if result.get("status") == "timed_out":
            raise ValueError("시간 초과 결과에는 버전 2가 필요합니다.")
        return

    reasons = {
        "passed": "completed",
        "failed": "operation_failed",
        "timed_out": "deadline_exceeded",
    }

    status = result.get("status")
    if status not in reasons:
        raise ValueError("잘못된 결과 상태입니다.")

    if result.get("termination_reason") != reasons[status]:
        raise ValueError("결과 상태와 종료 이유가 일치하지 않습니다.")

    steps = result.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ValueError("단계별 결과가 필요합니다.")

    for step in steps:
        if not isinstance(step, dict):
            raise ValueError("잘못된 단계 결과입니다.")

        counts = [
            step.get("planned"),
            step.get("attempted"),
            step.get("completed"),
        ]

        if any(type(value) is not int for value in counts):
            raise ValueError("연산 수는 정수여야 합니다.")

        planned, attempted, completed = counts

        if not 0 <= completed <= attempted <= planned or planned <= 0:
            raise ValueError("단계별 연산 수가 일치하지 않습니다.")

        step_status = step.get("status")

        if step_status == "passed":
            if completed != planned:
                raise ValueError("완료되지 않은 단계를 성공으로 보고했습니다.")

            if step.get("failure") is not None:
                raise ValueError("성공 단계에 실패 정보가 있습니다.")

        elif step_status == "failed":
            failure = step.get("failure")

            if not isinstance(failure, dict):
                raise ValueError("실패한 단계에 실패 정보가 없습니다.")

            for key in ("operation", "path", "message"):
                value = failure.get(key)
                if not isinstance(value, str) or not value.strip():
                    raise ValueError(f"실패 정보의 {key}가 필요합니다.")

            error_number = failure.get("errno")
            if error_number is not None:
                if type(error_number) is not int or error_number <= 0:
                    raise ValueError("errno는 양의 정수 또는 null이어야 합니다.")

        else:
            raise ValueError("잘못된 단계 상태입니다.")
