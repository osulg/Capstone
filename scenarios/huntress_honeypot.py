"""Huntress 허니팟 미끼 사전 확인과 접근 관찰."""

import argparse
import errno
import json
import math
import stat
import time
from pathlib import Path

from guardfs.common.paths import get_honeypot_dir

DECOY_NAMES = (
    "id_rsa",
    "credentials",
    "config",
    ".env",
    "api_token.txt",
)
ACCESS_DELAY_SECONDS = 0.1


def execute_task(args):
    """기존 미끼를 확인하거나 접근하고 결과를 기록한다."""
    root = Path(
        get_honeypot_dir(str(args.underlay if args.action == "check" else args.mount))
    )

    result = {
        "action": args.action,
        "status": "passed",
        "planned": len(DECOY_NAMES),
        "attempted": 0,
        "completed": 0,
        "failure": None,
        "operations": [],
        "honeypot_root": str(root),
        "scope": (
            "미끼 준비 확인"
            if args.action == "check"
            else "접근 결과 관찰이며 정책 차단 판정은 별도"
        ),
    }

    deadline = time.monotonic() + args.timeout
    current_path = root

    try:
        for index, name in enumerate(DECOY_NAMES):
            current_path = root / name

            if time.monotonic() >= deadline:
                raise TimeoutError("허니팟 작업 제한 시간을 초과했습니다.")

            result["attempted"] += 1

            if args.action == "check":
                # 사전 확인은 underlay에서만 수행한다.
                # 심볼릭 링크를 미끼 파일로 인정하지 않는다.
                file_stat = current_path.lstat()

                if not stat.S_ISREG(file_stat.st_mode):
                    raise ValueError(f"미끼가 일반 파일이 아닙니다: {name}")

                if file_stat.st_size == 0:
                    raise ValueError(f"미끼 내용이 비어 있습니다: {name}")

                operation = {
                    "name": name,
                    "path": str(current_path),
                    "status": "passed",
                    "prepared": True,
                    "size": file_stat.st_size,
                }

            else:
                # 실제 접근은 mount에서 수행한다.
                # 사전 exists·stat 호출 없이 읽기 접근을 시도한다.
                try:
                    with current_path.open("rb") as stream:
                        data = stream.read()

                    operation = {
                        "name": name,
                        "path": str(current_path),
                        "status": "passed",
                        "access": "read",
                        "bytes": len(data),
                        "errno": None,
                    }

                except OSError as error:
                    if error.errno in (errno.EACCES, errno.EPERM):
                        access = "denied"
                    elif error.errno == errno.ENOENT:
                        access = "missing"
                    else:
                        access = "error"

                    # 관찰 완료와 읽기 성공은 다른 의미다.
                    operation = {
                        "name": name,
                        "path": str(current_path),
                        "status": "passed",
                        "access": access,
                        "errno": error.errno,
                        "message": str(error),
                    }

            result["completed"] += 1
            result["operations"].append(operation)

            if args.action == "access" and index < len(DECOY_NAMES) - 1:
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    time.sleep(min(ACCESS_DELAY_SECONDS, remaining))

    except (OSError, ValueError) as error:
        result["status"] = "timed_out" if isinstance(error, TimeoutError) else "failed"
        result["failure"] = {
            "operation": args.action,
            "path": str(current_path),
            "errno": getattr(error, "errno", None),
            "message": str(error),
        }

    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("check", "access"))
    parser.add_argument("--mount", type=Path, required=True)
    parser.add_argument("--underlay", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    if not args.mount.is_absolute() or not args.underlay.is_absolute():
        parser.error("mount와 underlay는 절대 경로여야 합니다.")

    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("제한 시간은 유한한 양수여야 합니다.")

    result = execute_task(args)
    print(json.dumps(result, ensure_ascii=False), flush=True)

    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
