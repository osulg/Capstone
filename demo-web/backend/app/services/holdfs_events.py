"""HoldFS 로그를 변경하지 않고 실행 관련 이벤트를 수집한다."""

import json
import os
import posixpath
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from guardfs.common.paths import (
    FILESECURITY_LOG_PATH,
    get_event_log_path,
)

LogSource = Literal["filesystem", "policy"]


@dataclass(frozen=True)
class LogCheckpoint:
    """실행 전에 확인한 로그 파일과 읽기 시작 위치."""

    source: LogSource
    path: Path
    device: int
    inode: int
    offset: int

    # 같은 파일이 잘린 후 다시 커진 경우도 일부 확인하기 위한 값.
    anchor: bytes


@dataclass(frozen=True)
class EventScope:
    """수집 대상 PID와 실제 로그에 기록되는 작업 경로."""

    pids: frozenset[int]

    # 로그는 Linux 경로이므로 Windows에서도 POSIX 방식으로 비교한다.
    roots: tuple[str, ...]

    # JSONL의 이벤트 발생 시각을 추가로 제한할 때 사용한다.
    started_at_ns: int
    observed_until_ns: int

    # 하위 경로를 포함하지 않고 정확히 일치하는 경로만 허용한다.
    exact_paths: tuple[str, ...] = ()

    def __post_init__(self):
        if not self.pids or any(type(pid) is not int or pid <= 0 for pid in self.pids):
            raise ValueError("수집 대상 PID가 필요합니다.")

        if not self.roots and not self.exact_paths:
            raise ValueError("수집할 작업 경로가 필요합니다.")

        if any(not posixpath.isabs(path) for path in (*self.roots, *self.exact_paths)):
            raise ValueError("작업 경로는 Linux 절대 경로여야 합니다.")

        if self.started_at_ns > self.observed_until_ns:
            raise ValueError("이벤트 조회 시간 범위가 올바르지 않습니다.")


@dataclass
class EventCollection:
    """수집 결과. 이벤트가 없다고 정책 검증 성공을 의미하지 않는다."""

    # PID와 작업 경로가 모두 일치하는 이벤트.
    events: list[dict] = field(default_factory=list)

    # PID는 일치하지만 경로가 없어 실행 경로와 연결하지 못한 이벤트.
    # DATA_APPLIED 등의 정책 기록이 여기에 들어갈 수 있다.
    pid_only_events: list[dict] = field(default_factory=list)

    # 수집 실패나 기록 손상. 판정 단계에서 반드시 확인해야 한다.
    issues: list[str] = field(default_factory=list)

    # 아직 쓰는 중인 마지막 줄 또는 정책 블록이 있는지 여부.
    pending_record: bool = False


def capture_log(
    path: str | Path,
    source: LogSource,
) -> LogCheckpoint:
    """실행 전에 현재 로그의 끝을 기록한다.

    파일이 없거나 읽을 수 없으면 예외를 전달한다.
    수집 실패를 빈 로그로 숨기지 않는다.
    """

    path = Path(path)

    with path.open("rb") as stream:
        info = os.fstat(stream.fileno())
        offset = info.st_size

        stream.seek(max(0, offset - 64))
        anchor = stream.read(offset - stream.tell())

    return LogCheckpoint(
        source=source,
        path=path,
        device=info.st_dev,
        inode=info.st_ino,
        offset=offset,
        anchor=anchor,
    )


def capture_sources(underlay: str | Path) -> tuple[LogCheckpoint, ...]:
    """공통 경로 정의를 사용해 두 로그의 시작 위치를 기록한다."""

    return (
        capture_log(
            get_event_log_path(str(underlay)),
            "filesystem",
        ),
        capture_log(
            FILESECURITY_LOG_PATH,
            "policy",
        ),
    )


def _read_added_text(
    checkpoint: LogCheckpoint,
    max_bytes: int,
) -> str:
    """기록한 위치 이후의 내용을 읽는다. 로그 자체는 수정하지 않는다."""

    with checkpoint.path.open("rb") as stream:
        info = os.fstat(stream.fileno())

        if (info.st_dev, info.st_ino) != (
            checkpoint.device,
            checkpoint.inode,
        ):
            raise ValueError("조회 중 로그 파일이 교체됐습니다.")

        if info.st_size < checkpoint.offset:
            raise ValueError("조회 중 로그 파일이 잘렸습니다.")

        anchor_start = checkpoint.offset - len(checkpoint.anchor)
        stream.seek(anchor_start)

        if stream.read(len(checkpoint.anchor)) != checkpoint.anchor:
            raise ValueError("로그의 기존 내용이 변경됐습니다.")

        size = info.st_size - checkpoint.offset

        if size > max_bytes:
            raise ValueError("수집 허용 크기를 초과했습니다.")

        stream.seek(checkpoint.offset)
        data = stream.read(size)

        if len(data) != size:
            raise ValueError("조회 중 로그 크기가 변경됐습니다.")

    return data.decode("utf-8")


def _matches_path(path: str, roots: tuple[str, ...]) -> bool:
    """단순 접두사 대신 디렉터리 경계로 경로를 비교한다."""

    if not posixpath.isabs(path):
        return False

    normalized = posixpath.normpath(path)

    return any(
        posixpath.commonpath((normalized, posixpath.normpath(root)))
        == posixpath.normpath(root)
        for root in roots
    )


def _add_event(
    record: dict,
    scope: EventScope,
    result: EventCollection,
) -> None:
    """PID와 경로를 기준으로 분류한다. 정책 판정은 하지 않는다."""

    if record["pid"] not in scope.pids:
        return

    paths = [
        value
        for value in (
            record.get("path"),
            record.get("new_path"),
        )
        if isinstance(value, str) and value
    ]

    if not paths:
        result.pid_only_events.append(record)
        return

    normalized_exact_paths = {
        posixpath.normpath(path) for path in scope.exact_paths
    }
    if any(
        _matches_path(path, scope.roots)
        or (posixpath.isabs(path) and posixpath.normpath(path) in normalized_exact_paths)
        for path in paths
    ):
        result.events.append(record)


def _parse_filesystem(
    text: str,
    scope: EventScope,
    result: EventCollection,
) -> None:
    for number, line in enumerate(text.splitlines(keepends=True), start=1):
        # 쓰는 중인 마지막 줄은 손상으로 단정하지 않고 다음 수집을 기다린다.
        if not line.endswith("\n"):
            result.pending_record = True
            continue

        if not line.strip():
            continue

        try:
            raw = json.loads(line)

            if not isinstance(raw, dict):
                raise ValueError("이벤트 객체가 아닙니다.")

            if type(raw.get("pid")) is not int or raw["pid"] <= 0:
                raise ValueError("PID가 올바르지 않습니다.")

            if type(raw.get("ts_ns")) is not int:
                raise ValueError("이벤트 시각이 올바르지 않습니다.")

            if not isinstance(raw.get("op"), str) or not raw["op"]:
                raise ValueError("연산 이름이 없습니다.")

            if not isinstance(raw.get("path"), str):
                raise ValueError("경로 형식이 올바르지 않습니다.")

            if "applied" in raw and type(raw["applied"]) is not bool:
                raise ValueError("applied 형식이 올바르지 않습니다.")

            if raw.get("new_path") is not None and not isinstance(raw["new_path"], str):
                raise ValueError("변경 경로 형식이 올바르지 않습니다.")

            if not (scope.started_at_ns <= raw["ts_ns"] <= scope.observed_until_ns):
                continue

            _add_event(
                {
                    **raw,
                    "source": "filesystem",
                },
                scope,
                result,
            )

        except (json.JSONDecodeError, ValueError) as error:
            result.issues.append(f"파일 이벤트 {number}번째 기록 해석 실패: {error}")


def _parse_policy(
    text: str,
    scope: EventScope,
    result: EventCollection,
) -> None:
    # 정책 로그는 빈 줄로 끝나는 MEDIUM/HIGH 블록이다.
    normalized = text.replace("\r\n", "\n")
    blocks = normalized.split("\n\n")

    if blocks[-1].strip():
        result.pending_record = True

    for number, block in enumerate(blocks[:-1], start=1):
        if not block.strip():
            continue

        try:
            lines = block.splitlines()

            if lines[0] not in ("[MEDIUM]", "[HIGH]"):
                raise ValueError("지원하지 않는 정책 로그 블록입니다.")

            fields = {}

            for line in lines[1:]:
                key, separator, value = line.partition(": ")

                if not separator:
                    raise ValueError("정책 로그 필드 형식이 올바르지 않습니다.")

                if key in fields:
                    raise ValueError("정책 로그에 중복 필드가 있습니다.")

                fields[key] = value

            required = ("Time", "PID", "Target", "Action", "Result")

            if any(key not in fields for key in required):
                raise ValueError("필수 정책 필드가 없습니다.")

            pid = int(fields["PID"])

            if pid <= 0 or not fields["Action"] or not fields["Result"]:
                raise ValueError("정책 이벤트 값이 올바르지 않습니다.")

            _add_event(
                {
                    "source": "policy",
                    "level": lines[0][1:-1],
                    "pid": pid,
                    "path": fields["Target"],
                    "op": fields["Action"],
                    "result": fields["Result"],
                    "reason": fields.get("Reason", ""),
                    # 현재 정책 로그는 시간대 없는 로컬 시각이다.
                    # 임의로 UTC로 변환하지 않고 원문을 보관한다.
                    "logged_at": fields["Time"],
                },
                scope,
                result,
            )

        except ValueError as error:
            result.issues.append(f"정책 이벤트 {number}번째 기록 해석 실패: {error}")


def collect_events(
    checkpoint: LogCheckpoint,
    scope: EventScope,
    *,
    max_bytes: int = 4 * 1024 * 1024,
) -> EventCollection:
    """실행 전 기록한 위치 이후의 이벤트를 수집한다.

    같은 checkpoint로 다시 호출하면 같은 구간을 다시 읽는다.
    호출 결과를 단순 누적하지 말고 최신 수집 결과로 교체해야 한다.
    """

    if max_bytes <= 0:
        raise ValueError("수집 허용 크기는 양수여야 합니다.")

    result = EventCollection()

    try:
        text = _read_added_text(checkpoint, max_bytes)
    except (OSError, UnicodeDecodeError, ValueError) as error:
        result.issues.append(f"{checkpoint.source} 로그 수집 실패: {error}")
        return result

    if checkpoint.source == "filesystem":
        _parse_filesystem(text, scope, result)
    else:
        _parse_policy(text, scope, result)

    return result
