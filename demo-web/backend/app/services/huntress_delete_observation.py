"""프로세스 정리 이후 로그 파일의 실제 상태를 관찰한다."""

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from scenarios.huntress_config import DELETE_FILES

PROJECT_ROOT = Path(__file__).resolve().parents[4]
FILE_STATES = {"matched", "changed", "missing", "unreadable"}


def observe_deleted_files(record, *, cleanup_confirmed):
    result = {
        "status": "unknown",
        "observed_at": None,
        "cleanup_confirmed": cleanup_confirmed,
        "files": [],
        "counts": {},
        "issues": [],
        "scope": "프로세스 정리 이후 관찰 시점의 파일 상태",
    }

    if record.scenario_id != "S02" or record.mode != "delete":
        result["issues"].append("S02 로그 삭제 실행이 아닙니다.")
        return result

    if not cleanup_confirmed:
        result["issues"].append("프로세스 정리를 확인하지 못했습니다.")
        return result

    workspace = record.workspace
    if workspace is None or workspace.name != f"s02_{record.run_id}":
        result["issues"].append("실행 작업 경로를 확인하지 못했습니다.")
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
                    "scenarios.huntress_delete_tasks",
                    "inspect",
                    "--root",
                    root,
                    "--timeout",
                    "5",
                ],
                cwd=PROJECT_ROOT,
                capture_output=True,
                timeout=7,
                check=True,
            )

            payload = json.loads(completed.stdout.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("파일 상태 결과가 객체가 아닙니다.")

            if (
                payload.get("action") != "inspect"
                or payload.get("status") != "passed"
                or payload.get("failure") is not None
            ):
                raise ValueError("파일 상태 확인이 완료되지 않았습니다.")

            for key in ("planned", "attempted", "completed"):
                value = payload.get(key)
                if type(value) is not int or value != len(DELETE_FILES):
                    raise ValueError("파일 상태 확인 수가 다릅니다.")

            operations = payload.get("operations")
            if not isinstance(operations, list) or len(operations) != len(DELETE_FILES):
                raise ValueError("파일 상태 목록이 다릅니다.")

            states = {}
            for name, item in zip(DELETE_FILES, operations):
                if not isinstance(item, dict):
                    raise ValueError("파일 상태 기록이 객체가 아닙니다.")

                if (
                    item.get("name") != name
                    or item.get("path") != str(Path(root) / name)
                    or item.get("state") not in FILE_STATES
                ):
                    raise ValueError("파일 상태의 이름·경로·값이 다릅니다.")

                states[name] = item["state"]

            observations[side] = states

        except (
            OSError,
            subprocess.SubprocessError,
            UnicodeDecodeError,
            ValueError,
        ) as error:
            result["issues"].append(
                f"{side} 파일 상태 확인 실패: {type(error).__name__}: {error}"
            )

    result["files"] = [
        {
            "name": name,
            "mount": observations.get("mount", {}).get(name, "unreadable"),
            "underlay": observations.get("underlay", {}).get(name, "unreadable"),
        }
        for name in DELETE_FILES
    ]

    result["counts"] = {
        side: {
            state: sum(item[side] == state for item in result["files"])
            for state in sorted(FILE_STATES)
        }
        for side in ("mount", "underlay")
    }

    # 파일 부재는 준비 실패 때문일 수도 있으므로 삭제 성공으로 단정하지 않는다.
    # 내용 일치 역시 정책 차단의 직접 근거는 아니다.
    if not result["issues"] and all(
        item[side] != "unreadable"
        for item in result["files"]
        for side in ("mount", "underlay")
    ):
        result["status"] = "observed"

    result["observed_at"] = datetime.now(UTC).isoformat()
    return result
