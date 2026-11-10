"""Akira 더미 VM 파일 준비·부분 덮어쓰기·상태 조회."""

import argparse
import json
import math
import os
import re
import stat
import time
from pathlib import Path

from scenarios.akira_config import (
    CHUNK_SIZE,
    DELAY_SECONDS,
    ENCRYPTION_PERCENT,
    FILE_NAMES,
    FILE_SIZE,
    NEW_EXT,
    NOTE_BODY,
    NOTE_NAME,
    expected_content,
)


def inspect_file(path, expected):
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            return "unreadable"

        with path.open("rb") as stream:
            actual = stream.read(len(expected) + 1)

        return "matched" if actual == expected else "changed"
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "unreadable"


def execute_task(action, root, mode, timeout):
    content = expected_content()
    deadline = time.monotonic() + timeout
    planned = len(FILE_NAMES) * 3 + 1 if action == "attack" else len(FILE_NAMES)

    result = {
        "action": action,
        "mode": mode,
        "status": "passed",
        "planned": planned,
        "attempted": 0,
        "completed": 0,
        "failure": None,
        "operations": [],
    }

    current_path = root
    current_operation = action

    def check_deadline():
        if time.monotonic() >= deadline:
            raise TimeoutError("Akira 작업 제한 시간을 초과했습니다.")

    def perform(operation, path, function):
        nonlocal current_path, current_operation
        current_path = path
        current_operation = operation
        check_deadline()
        result["attempted"] += 1
        details = function() or {}
        result["operations"].append(
            {
                "operation": operation,
                "path": str(path),
                **details,
            }
        )
        result["completed"] += 1

    def verify(path):
        while True:
            check_deadline()
            state = inspect_file(path, content)
            if state == "matched":
                return {"state": state}
            if state == "unreadable":
                raise OSError(f"파일을 확인할 수 없습니다: {path}")
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))

    def prepare(path):
        # 기존 파일은 덮어쓰지 않는다.
        with path.open("xb") as stream:
            stream.write(content)
        return {"bytes": len(content)}

    def read(path):
        # 기존 CLI처럼 덮어쓰기 전에 파일을 읽는다.
        with path.open("rb") as stream:
            while stream.read(CHUNK_SIZE):
                check_deadline()

    def overwrite(path):
        length = int(FILE_SIZE * ENCRYPTION_PERCENT / 100)
        offset = 0 if mode == "head" else FILE_SIZE - length
        written = 0

        with path.open("r+b", buffering=0) as stream:
            stream.seek(offset)

            while written < length:
                check_deadline()
                data = os.urandom(min(CHUNK_SIZE, length - written))
                count = stream.write(data)

                if count is None or count <= 0:
                    raise OSError("부분 덮어쓰기가 진행되지 않았습니다.")

                written += count

        return {"offset": offset, "bytes": written}

    def rename(path):
        destination = path.with_name(path.name + NEW_EXT)
        if destination.exists():
            raise FileExistsError(str(destination))
        path.rename(destination)
        return {"new_path": str(destination)}

    def write_note():
        with (root / NOTE_NAME).open("x", encoding="utf-8") as stream:
            stream.write(NOTE_BODY)

    try:
        if action not in ("prepare", "verify", "attack", "inspect"):
            raise ValueError("지원하지 않는 작업입니다.")

        if mode not in ("head", "tail"):
            raise ValueError("지원하지 않는 덮어쓰기 위치입니다.")

        if not root.is_absolute() or not re.fullmatch(r"s03_[0-9a-f]{32}", root.name):
            raise ValueError("Akira 실행별 작업 경로가 필요합니다.")

        if not stat.S_ISDIR(root.lstat().st_mode):
            raise ValueError("작업 경로가 실제 디렉터리가 아닙니다.")

        for index, name in enumerate(FILE_NAMES):
            path = root / name

            if action == "prepare":
                perform("create", path, lambda: prepare(path))

            elif action == "verify":
                perform("verify", path, lambda: verify(path))

            elif action == "inspect":
                perform(
                    "inspect",
                    path,
                    lambda: {
                        "original": inspect_file(path, content),
                        "renamed": inspect_file(
                            path.with_name(path.name + NEW_EXT),
                            content,
                        ),
                    },
                )

            else:
                perform("read", path, lambda: read(path))
                perform("overwrite", path, lambda: overwrite(path))
                perform("rename", path, lambda: rename(path))

                if index < len(FILE_NAMES) - 1:
                    time.sleep(min(DELAY_SECONDS, max(0, deadline - time.monotonic())))

        if action == "attack":
            perform("note", root / NOTE_NAME, write_note)

    except (OSError, ValueError) as error:
        result["status"] = "timed_out" if isinstance(error, TimeoutError) else "failed"
        result["failure"] = {
            "operation": current_operation,
            "path": str(current_path),
            "errno": getattr(error, "errno", None),
            "message": str(error) or "Akira 작업 실패",
        }

    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action",
        choices=("prepare", "verify", "attack", "inspect"),
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--mode", choices=("head", "tail"), required=True)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("제한 시간은 유한한 양수여야 합니다.")

    report = execute_task(
        args.action,
        args.root,
        args.mode,
        args.timeout,
    )
    print(json.dumps(report, ensure_ascii=False), flush=True)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
