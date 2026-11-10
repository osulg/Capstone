"""Huntress 허니팟 미끼 사전 확인과 접근 관찰 작업."""

import argparse
import errno
import json
import math
import os
import stat
import sys
import time
from pathlib import Path

from guardfs.common.paths import get_honeypot_dir
from scenarios.huntress_config import (
    HONEYPOT_DELAY_SECONDS,
    HONEYPOT_FILES,
)


def honeypot_paths(mount, underlay):
    """공통 설정의 underlay 허니팟을 mount 경로에 대응시킨다."""
    mount = Path(os.path.abspath(Path(mount).expanduser()))
    underlay = Path(underlay).expanduser().resolve()

    source = Path(get_honeypot_dir(str(underlay)))
    relative = source.relative_to(underlay)

    return mount / relative, source


def emit_access_event(path, phase, **details):
    """최종 JSON을 받지 못해도 접근 시점의 진단 기록을 남긴다."""
    event = {
        "pid": os.getpid(),
        "path": str(path),
        "phase": phase,
        "ts_ns": time.time_ns(),
        **details,
    }
    print(
        "HUNTRESS_ACCESS " + json.dumps(event, ensure_ascii=False),
        file=sys.stderr,
        flush=True,
    )


def execute_task(action, mount, underlay, timeout):
    mount_honeypot, underlay_honeypot = honeypot_paths(
        mount,
        underlay,
    )
    target = underlay_honeypot if action == "check" else mount_honeypot

    result = {
        "action": action,
        "status": "passed",
        "planned": len(HONEYPOT_FILES),
        "attempted": 0,
        "completed": 0,
        "failure": None,
        "operations": [],
    }

    deadline = time.monotonic() + timeout
    current_path = target

    try:
        if action not in ("check", "access"):
            raise ValueError("지원하지 않는 허니팟 작업입니다.")

        if action == "check":
            # 사전 확인 과정에서는 mount의 미끼에 접근하지 않는다.
            if not stat.S_ISDIR(target.lstat().st_mode):
                raise ValueError("허니팟 경로가 실제 디렉터리가 아닙니다.")

        for index, name in enumerate(HONEYPOT_FILES):
            current_path = target / name

            if time.monotonic() >= deadline:
                raise TimeoutError("허니팟 작업 제한 시간을 초과했습니다.")

            result["attempted"] += 1

            if action == "check":
                metadata = current_path.lstat()

                # 심볼릭 링크와 디렉터리는 미끼 파일로 인정하지 않는다.
                if not stat.S_ISREG(metadata.st_mode):
                    raise ValueError(f"미끼가 일반 파일이 아닙니다: {name}")

                observation = {
                    "name": name,
                    "path": str(current_path),
                    "outcome": "ready",
                    "bytes": metadata.st_size,
                    "errno": None,
                }

            else:
                # 사전 stat이나 resolve도 탐지를 유발할 수 있으므로
                # mount에서는 실제 읽기 접근부터 시도한다.
                emit_access_event(current_path, "attempt")

                try:
                    with current_path.open("rb") as stream:
                        # 미끼 본문을 결과나 로그에 노출하지 않는다.
                        data = stream.read(4097)

                    observation = {
                        "name": name,
                        "path": str(current_path),
                        "outcome": "read_succeeded",
                        "sampled_bytes": len(data),
                        "errno": None,
                    }

                except OSError as error:
                    if error.errno in (errno.EACCES, errno.EPERM):
                        outcome = "permission_denied"
                    elif error.errno == errno.ENOENT:
                        outcome = "missing"
                    else:
                        outcome = "access_error"

                    observation = {
                        "name": name,
                        "path": str(current_path),
                        "outcome": outcome,
                        "errno": error.errno,
                        "message": str(error),
                    }

                emit_access_event(
                    current_path,
                    "observed",
                    outcome=observation["outcome"],
                    errno=observation["errno"],
                )

            # 접근 모드에서는 관찰 결과를 기록한 경로 수를 센다.
            # 읽기 성공 수나 정책 차단 수가 아니다.
            result["completed"] += 1
            result["operations"].append(observation)

            if action == "access" and index < len(HONEYPOT_FILES) - 1:
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    time.sleep(min(HONEYPOT_DELAY_SECONDS, remaining))

    except (OSError, ValueError) as error:
        result["status"] = "timed_out" if isinstance(error, TimeoutError) else "failed"
        result["failure"] = {
            "operation": action,
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

    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("제한 시간은 유한한 양수여야 합니다.")

    if not args.mount.is_absolute() or not args.underlay.is_absolute():
        parser.error("mount와 underlay는 절대 경로여야 합니다.")

    result = execute_task(
        args.action,
        args.mount,
        args.underlay,
        args.timeout,
    )

    print(json.dumps(result, ensure_ascii=False), flush=True)
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
