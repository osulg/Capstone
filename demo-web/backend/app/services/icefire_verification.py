"""실행 결과와 분리한 IceFire 보호 검증. 관찰 시점의 증거만 판정한다."""

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from scenarios.icefire_config import FILE_COUNT


def verify_protection(record, *, cleanup_confirmed: bool) -> dict:
    result = {
        "status": "unknown", "reason": "보호 검증에 필요한 근거가 부족합니다.",
        "observed_at": datetime.now(UTC).isoformat(),
        "files": [], "blocking_events": [],
        "cleanup_confirmed": cleanup_confirmed,
        "scope": "이번 실행의 문서 내용과 경로가 있는 차단 이벤트; 후속 지연 작업 완료는 보장하지 않음",
    }
    payload = record.result or {}
    if not cleanup_confirmed or record.status == "cancelled":
        result["reason"] = "실행 중단 또는 프로세스 정리 미확인으로 판정하지 않습니다."
        return result
    if payload.get("execution_scope") != "full" or payload.get("attack_started") is not True:
        return result
    workspace = record.workspace
    if workspace is None or workspace.name != f"s01_{record.run_id}":
        return result
    attackers = [p for p in record.processes if p.role == "icefire_attack" and p.start_time_ticks is not None]
    if len(attackers) != 1:
        return result
    events = record.event_collection
    if events is not None:
        root = Path(workspace.underlay_path)
        for event in events.events:
            path = event.get("path")
            if (event.get("source") != "policy" or event.get("pid") != attackers[0].pid
                    or event.get("level") != "HIGH" or event.get("result") != "BLOCKED"
                    or event.get("op") != "WRITE" or not isinstance(path, str)):
                continue
            if Path(path).is_relative_to(root):
                result["blocking_events"].append(event)
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "scenarios.verify_icefire",
             "--mount", str(Path(workspace.mount_path).parent),
             "--underlay", str(Path(workspace.underlay_path).parent),
             "--workspace", workspace.name],
            cwd=str(Path(__file__).resolve().parents[4]),
            capture_output=True, timeout=15, check=True,
        )
        files = json.loads(completed.stdout.decode("utf-8"))
        expected = [f"doc_{i:03d}{('.docx', '.pdf', '.xlsx')[i % 3]}" for i in range(FILE_COUNT)]
        if not isinstance(files, list) or any(not isinstance(item, dict) for item in files):
            raise ValueError("잘못된 문서 검증 결과입니다.")
        if [item.get("name") for item in files] != expected:
            raise ValueError("문서 검증 목록이 일치하지 않습니다.")
        result["files"] = files
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        result["reason"] = f"문서 검증을 완료하지 못했습니다: {error}"
        return result
    states = [item.get(side) for item in files for side in ("mount", "underlay")]
    if any(state in ("changed", "missing") for state in states):
        result.update(status="failed", reason="문서 변경 또는 누락이 확인됐습니다.")
    elif any(state != "matched" for state in states):
        result["reason"] = "일부 문서 내용을 확인하지 못했습니다."
    elif not result["blocking_events"]:
        result["reason"] = "원본은 일치하지만 해당 공격의 쓰기 차단 근거가 없습니다."
    elif events is None or events.issues or events.pending_record:
        result["reason"] = "원본과 차단 근거는 있으나 로그 수집이 불완전합니다."
    else:
        result.update(status="passed", reason=f"공격 쓰기 차단과 문서 {FILE_COUNT}개 원본 보존, 프로세스 정리를 확인했습니다.")
    return result
