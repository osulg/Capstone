"""Huntress 허니팟 접근 결과와 파일 시스템 차단 근거 검증."""

import posixpath
from datetime import UTC, datetime

from app.services.huntress_validation import validate_honeypot_success


def verify_honeypot_protection(record, *, cleanup_confirmed: bool) -> dict:
    result = {
        "status": "unknown",
        "reason": "허니팟 보호 검증에 필요한 근거가 부족합니다.",
        "observed_at": datetime.now(UTC).isoformat(),
        "cleanup_confirmed": cleanup_confirmed,
        "blocking_events": [],
        "scope": "이번 실행의 허니팟 읽기 접근 차단",
    }

    if record.scenario_id != "S02" or record.mode != "honeypot":
        result["reason"] = "S02 허니팟 실행이 아닙니다."
        return result

    if not cleanup_confirmed or record.status == "cancelled":
        result["reason"] = (
            "사용자 중단 또는 프로세스 정리 미확인으로 판정하지 않습니다."
        )
        return result

    payload = record.result
    if not isinstance(payload, dict) or payload.get("status") != "passed":
        result["reason"] = "완료된 허니팟 접근 결과가 없어 판정하지 않습니다."
        return result

    # 자식 작업의 PID, 실행 순서, 미끼 목록과 경로를 먼저 검사한다.
    try:
        validate_honeypot_success(payload, record)
    except ValueError as error:
        result["reason"] = f"허니팟 실행 결과를 검증하지 못했습니다: {error}"
        return result

    access_task = next(
        task
        for task in payload["task_results"]
        if task["role"] == "huntress_honeypot_access"
    )
    operations = access_task["operations"]

    # 실제 읽기가 성공했다면 해당 실행의 읽기 차단은 실패한 것이다.
    if any(item["outcome"] == "read_succeeded" for item in operations):
        result.update(
            status="failed",
            reason="일부 허니팟 미끼의 읽기가 성공했습니다.",
        )
        return result

    # 파일 부재나 기타 접근 오류를 보호 성공으로 간주하지 않는다.
    if any(item["outcome"] != "permission_denied" for item in operations):
        result["reason"] = (
            "파일 부재 또는 기타 접근 오류가 있어 차단을 확정하지 않습니다."
        )
        return result

    collection = record.event_collection
    if collection is None:
        result["reason"] = "파일 시스템 이벤트 수집 결과가 없습니다."
        return result

    observation = payload["honeypot_observation"]
    roots = {
        posixpath.normpath(observation["mount_root"]),
        posixpath.normpath(observation["underlay_root"]),
    }

    def matching_events(operation):
        target = next(
            item for item in observation["targets"] if item["name"] == operation["name"]
        )
        allowed_paths = roots | {
            posixpath.normpath(target["mount_path"]),
            posixpath.normpath(target["underlay_path"]),
        }

        matches = []
        for event in collection.events:
            path = event.get("path")

            if (
                event.get("source") != "filesystem"
                or event.get("pid") != access_task["pid"]
                or event.get("op") not in ("lookup", "open", "read")
                or event.get("applied") is not False
                or not isinstance(path, str)
                or not posixpath.isabs(path)
            ):
                continue

            if posixpath.normpath(path) in allowed_paths:
                matches.append(event)

        return matches

    for operation in operations:
        matches = matching_events(operation)

        if not matches:
            result["reason"] = "일부 접근 거부에 대응하는 차단 이벤트가 없습니다."
            return result

        for event in matches:
            if event not in result["blocking_events"]:
                result["blocking_events"].append(event)

    if collection.issues or collection.pending_record:
        result["reason"] = "차단 근거는 있으나 이벤트 수집이 불완전합니다."
        return result

    # 상위 디렉터리 차단이 여러 파일 접근을 막았을 수 있다.
    # 미끼별 차단 이벤트가 각각 발생했다고 표현하지 않는다.
    result.update(
        status="passed",
        reason="허니팟 읽기 접근 거부와 해당 PID·경로의 차단 근거를 확인했습니다.",
    )
    return result
