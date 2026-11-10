"""Huntress 일반 읽기의 준비·공개 확인·읽기 작업."""

import argparse
import json
import math
import stat
import time
from pathlib import Path

from scenarios.huntress_config import (
    READ_DELAY_SECONDS,
    READ_FILES,
    READ_PASSES,
    expected_content,
)


def task_path(workdir: Path, name: str) -> Path:
    """고정된 더미 파일 경로가 작업 디렉터리 안에 있는지 확인한다."""
    path = workdir / name

    if not path.resolve().is_relative_to(workdir.resolve()):
        raise ValueError("작업 디렉터리 밖의 경로입니다.")

    return path


def execute_task(args) -> dict:
    workdir = Path(args.workdir)
    expected = expected_content()

    planned = (
        len(READ_FILES) * READ_PASSES if args.action == "read" else len(READ_FILES)
    )

    result = {
        "action": args.action,
        "status": "passed",
        "planned": planned,
        "attempted": 0,
        "completed": 0,
        "failure": None,
        "operations": [],
    }

    deadline = time.monotonic() + args.timeout
    names = READ_FILES * READ_PASSES if args.action == "read" else READ_FILES

    def record_failure(name, path, error):
        timed_out = isinstance(error, TimeoutError)

        result["status"] = "timed_out" if timed_out else "failed"

        failure = {
            "operation": args.action,
            "path": str(path),
            "errno": getattr(error, "errno", None),
            "message": str(error),
        }

        # 첫 실패를 요약에 남기고 파일별 결과도 기록한다.
        if result["failure"] is None:
            result["failure"] = failure

        result["operations"].append(
            {
                "name": name,
                "status": "failed",
                **failure,
            }
        )

    for index, name in enumerate(names):
        path = workdir / name

        if time.monotonic() >= deadline:
            record_failure(
                name,
                path,
                TimeoutError("작업 제한 시간을 초과했습니다."),
            )
            break

        result["attempted"] += 1

        try:
            path = task_path(workdir, name)

            if args.action == "prepare":
                path.parent.mkdir(parents=True, exist_ok=True)

                # 기존 파일은 덮어쓰지 않는다.
                with path.open("xb") as stream:
                    stream.write(expected)

                details = {"bytes": len(expected)}

            elif args.action == "verify":
                while True:
                    try:
                        if not stat.S_ISREG(path.lstat().st_mode):
                            raise ValueError("일반 파일이 아닙니다.")

                        with path.open("rb") as stream:
                            matched = stream.read(len(expected) + 1) == expected
                    except FileNotFoundError:
                        matched = False

                    if matched:
                        break

                    if time.monotonic() >= deadline:
                        raise TimeoutError("더미 파일 공개 확인 시간이 초과됐습니다.")

                    time.sleep(0.1)

                details = {"content_matched": True}

            else:
                if not stat.S_ISREG(path.lstat().st_mode):
                    raise ValueError("일반 파일이 아닙니다.")

                # 기존 CLI처럼 파일 전체를 읽는다.
                with path.open("rb") as stream:
                    data = stream.read()

                details = {
                    "bytes": len(data),
                    "content_matched": data == expected,
                }

            result["completed"] += 1
            result["operations"].append(
                {
                    "name": name,
                    "path": str(path),
                    "status": "passed",
                    **details,
                }
            )

        except (OSError, ValueError) as error:
            record_failure(name, path, error)

            # 준비·확인 실패 시 다음 단계로 넘어가지 않는다.
            # 읽기는 기존 CLI처럼 다른 파일의 접근 결과도 관찰한다.
            if args.action != "read" or isinstance(error, TimeoutError):
                break

        if args.action == "read" and index < len(names) - 1:
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(READ_DELAY_SECONDS, remaining))

    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action",
        choices=("prepare", "verify", "read"),
    )
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("제한 시간은 유한한 양수여야 합니다.")

    if not args.workdir.is_absolute() or not args.workdir.is_dir():
        parser.error("존재하는 절대 작업 디렉터리가 필요합니다.")

    result = execute_task(args)
    print(json.dumps(result, ensure_ascii=False), flush=True)

    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
