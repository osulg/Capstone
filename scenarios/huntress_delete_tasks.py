"""Huntress 더미 로그 준비·삭제·보존 상태 확인 작업."""

import argparse
import errno
import json
import stat
import time
from pathlib import Path

from scenarios.huntress_config import (
    DELETE_DELAY_SECONDS,
    DELETE_FILES,
    expected_content,
)


def validate_root(root):
    """작업 루트가 실제 디렉터리인지 확인한다."""
    if not root.is_absolute():
        raise ValueError("작업 경로는 절대 경로여야 합니다.")

    if not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError("작업 경로가 실제 디렉터리가 아닙니다.")


def inspect_file(path, content):
    """파일 부재·내용 변경·확인 오류를 구분한다."""
    try:
        metadata = path.lstat()

        if not stat.S_ISREG(metadata.st_mode):
            return {"state": "unreadable", "reason": "not_regular"}

        with path.open("rb") as stream:
            actual = stream.read(len(content) + 1)

        return {
            "state": "matched" if actual == content else "changed",
        }
    except FileNotFoundError:
        return {"state": "missing"}
    except OSError as error:
        return {
            "state": "unreadable",
            "errno": error.errno,
            "reason": str(error),
        }


def execute_task(action, root, timeout):
    root = Path(root)
    content = expected_content()
    deadline = time.monotonic() + timeout

    report = {
        "action": action,
        "status": "passed",
        "planned": len(DELETE_FILES),
        "attempted": 0,
        "completed": 0,
        "failure": None,
        "operations": [],
    }

    def check_deadline():
        if time.monotonic() >= deadline:
            raise TimeoutError("로그 작업 제한 시간을 초과했습니다.")

    try:
        if action not in ("prepare", "verify", "delete", "inspect"):
            raise ValueError("지원하지 않는 로그 작업입니다.")

        validate_root(root)

        for index, name in enumerate(DELETE_FILES):
            check_deadline()
            path = root / name
            report["attempted"] += 1

            if action == "prepare":
                # 기존 파일을 덮어쓰지 않는다.
                with path.open("xb") as stream:
                    stream.write(content)

                operation = {
                    "name": name,
                    "path": str(path),
                    "outcome": "created",
                }

            elif action == "verify":
                # 준비 작업이 underlay에 반영될 때까지 재확인한다.
                while True:
                    check_deadline()
                    observation = inspect_file(path, content)

                    if observation["state"] == "matched":
                        break

                    if observation["state"] == "unreadable":
                        raise OSError(
                            observation.get("errno", errno.EIO),
                            observation.get("reason", "파일 확인 실패"),
                            str(path),
                        )

                    time.sleep(min(0.05, max(0, deadline - time.monotonic())))

                operation = {
                    "name": name,
                    "path": str(path),
                    "outcome": "matched",
                }

            elif action == "delete":
                try:
                    # 삭제 대상은 실행별 작업 폴더의 정해진 로그만 허용한다.
                    path.unlink()
                    outcome = "unlink_succeeded"
                    error_number = None
                except OSError as error:
                    error_number = error.errno

                    if error.errno in (errno.EACCES, errno.EPERM):
                        outcome = "permission_denied"
                    elif error.errno == errno.ENOENT:
                        outcome = "missing"
                    else:
                        outcome = "delete_error"

                operation = {
                    "name": name,
                    "path": str(path),
                    "outcome": outcome,
                    "errno": error_number,
                }

            else:
                operation = {
                    "name": name,
                    "path": str(path),
                    **inspect_file(path, content),
                }

            # 삭제 모드의 완료 수는 관찰 기록 수이며 삭제 성공 수가 아니다.
            report["operations"].append(operation)
            report["completed"] += 1

            if action == "delete" and index < len(DELETE_FILES) - 1:
                time.sleep(
                    min(
                        DELETE_DELAY_SECONDS,
                        max(0, deadline - time.monotonic()),
                    )
                )

    except (OSError, ValueError) as error:
        report["status"] = "timed_out" if isinstance(error, TimeoutError) else "failed"
        report["failure"] = {
            "operation": action,
            "errno": getattr(error, "errno", None),
            "message": str(error),
        }

    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action",
        choices=("prepare", "verify", "delete", "inspect"),
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    import math

    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("제한 시간은 유한한 양수여야 합니다.")

    report = execute_task(args.action, args.root, args.timeout)
    print(json.dumps(report, ensure_ascii=False), flush=True)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
