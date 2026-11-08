"""IceFire 준비·공개 확인·공격 모의 작업과 상세 결과 출력."""

import argparse
import json
import math
import os
import sys
import time
from contextlib import redirect_stdout
from pathlib import Path
from scenarios.icefire_config import FILE_COUNT, FILE_SIZE_KIB, expected_operations

from experiments.simulators.sim_scn_icefire import (
    NOTE_BODY,
    NOTE_NAME,
    SELF_MARKER,
    create_documents,
    document_bytes,
    lib,
)


def document_names(count: int) -> list[str]:
    extensions = (".docx", ".pdf", ".xlsx")
    return [
        f"doc_{index:03d}{extensions[index % len(extensions)]}"
        for index in range(count)
    ]


def execute_attack(args):
    """준비된 더미 문서를 변조하고 성공적으로 반환된 연산 수를 센다."""
    workdir = Path(args.workdir)
    names = document_names(args.files)
    size = args.size_kb * 1024
    result = {
        "action": "attack",
        "status": "passed",
        "planned": expected_operations("attack", len(names)),
        "attempted": 0,
        "completed": 0,
        "failure": None,
        "operations": [],
    }
    deadline = time.monotonic() + args.timeout
    current_operation = "attack"
    current_path = workdir
    operation_started = False

    def perform(operation, path, callback):
        nonlocal current_operation, current_path, operation_started
        current_operation, current_path = operation, Path(path)
        operation_started = False
        # 제한 시간에 도달하면 해당 파일 연산을 시작하지 않는다.
        if time.monotonic() >= deadline:
            raise TimeoutError("공격 작업 제한 시간을 초과했습니다.")
        result["attempted"] += 1
        operation_started = True
        callback()
        result["completed"] += 1
        result["operations"].append(
            {
                "operation": operation,
                "path": str(path),
                "status": "passed",
            }
        )

    try:
        for name in names:
            path = workdir / name
            renamed = path.with_name(path.name + ".ifire")
            perform("read", path, lambda: lib.read_file(str(path)))
            perform(
                "write", path, lambda: lib.overwrite_random(str(path), size, 16 * 1024)
            )
            perform("rename", path, lambda: lib.rename_to(str(path), str(renamed)))
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(0.15, remaining))
        perform(
            "write_note",
            workdir / NOTE_NAME,
            lambda: lib.write_note(str(workdir), NOTE_NAME, NOTE_BODY),
        )
        perform(
            "unlink_marker",
            workdir / SELF_MARKER,
            lambda: os.unlink(workdir / SELF_MARKER),
        )
    except OSError as error:
        result["status"] = "timed_out" if isinstance(error, TimeoutError) else "failed"
        result["failure"] = {
            "operation": current_operation,
            "path": str(current_path),
            "errno": error.errno,
            "message": str(error),
        }
        result["operations"].append(
            {
                **result["failure"],
                "status": "failed",
                "attempted": operation_started,
            }
        )
    return result


def execute_task(args):
    if args.action == "attack":
        return execute_attack(args)
    workdir = Path(args.workdir)
    names = document_names(args.files)
    size = args.size_kb * 1024

    # 준비는 문서 생성과 표식 생성, 확인은 문서와 표식 검사를 센다.
    result = {
        "action": args.action,
        "status": "passed",
        "planned": expected_operations(args.action, len(names)),
        "attempted": 0,
        "completed": 0,
        "failure": None,
    }

    current_path = workdir

    try:
        if args.action == "prepare":
            for name in names:
                current_path = workdir / name
                result["attempted"] += 1

                # 내부 fork 없이 현재 등록된 작업 PID가 생성한다.
                create_documents(str(workdir), [name], size)

                result["completed"] += 1

            current_path = workdir / SELF_MARKER
            result["attempted"] += 1
            current_path.write_bytes(b"icefire-sim-tool-marker\n")
            result["completed"] += 1

        else:
            # 파일 공개 대기는 관리자가 별도 제한 시간으로 감시한다.
            deadline = time.monotonic() + args.timeout

            for name in names:
                current_path = workdir / name
                expected = document_bytes(name, size)
                result["attempted"] += 1

                while True:
                    try:
                        with current_path.open("rb") as handle:
                            ready = handle.read(size + 1) == expected
                    except FileNotFoundError:
                        ready = False

                    if ready:
                        break

                    if time.monotonic() >= deadline:
                        raise TimeoutError("문서 공개 확인 시간이 초과됐습니다.")

                    time.sleep(0.1)

                result["completed"] += 1

            current_path = workdir / SELF_MARKER
            result["attempted"] += 1

            while True:
                try:
                    ready = current_path.read_bytes() == b"icefire-sim-tool-marker\n"
                except FileNotFoundError:
                    ready = False

                if ready:
                    break

                if time.monotonic() >= deadline:
                    raise TimeoutError("표식 공개 확인 시간이 초과됐습니다.")

                time.sleep(0.1)

            result["completed"] += 1

    except (OSError, ValueError) as error:
        timed_out = isinstance(error, TimeoutError)

        result["status"] = "timed_out" if timed_out else "failed"
        result["failure"] = {
            "operation": args.action,
            "path": str(current_path),
            "errno": (error.errno if isinstance(error, OSError) else None),
            "message": str(error),
        }

    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("prepare", "verify", "attack"))
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--files", type=int, default=FILE_COUNT)
    parser.add_argument("--size-kb", type=int, default=FILE_SIZE_KIB)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    if args.files <= 0 or args.size_kb <= 0:
        parser.error("파일 수와 크기는 양수여야 합니다.")

    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("제한 시간은 유한한 양수여야 합니다.")

    workdir = Path(args.workdir)
    if not workdir.is_absolute() or not workdir.is_dir():
        parser.error("존재하는 절대 작업 디렉터리가 필요합니다.")

    with redirect_stdout(sys.stderr):
        result = execute_task(args)

    print(json.dumps(result, ensure_ascii=False), flush=True)
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
