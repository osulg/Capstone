"""
EntropyDetector

1. 블록 검사
* 파일을 ENTROPY_HEADER_SIZE(기본 256B) 단위로 분할
* write offset 기준 블록 위치 계산
* 파일 전체 영역 검사

2. 분할 write 누적
* 동일 블록의 write 데이터를 실제 offset 기준으로 누적
* 동일 위치 재작성 시 최신 데이터로 덮어쓰기
* 블록 전체 수집 후 Shannon entropy 계산

3. 엔트로피 판정
* entropy >= ENTROPY_THRESHOLD(기본 7.0) → suspicious
* 여러 블록 완성 시 최대 entropy를 ev.entropy에 기록
* Stage 1, EventLogger, PidStats, Stage 2에서 공통 사용

4. 짧은 파일 판정
* 256B 미만 파일은 release 시 평가
* 최소 ENTROPY_MIN_SAMPLE_SIZE(기본 128B) 이상 필요
* entropy >= ENTROPY_SHORT_SAMPLE_THRESHOLD(기본 6.5) → suspicious

5. 상태 관리
* 상태 단위: (pid, realpath, block_index)
* 누적 시간 초과 시 불완전 블록 제거
* unlink/truncate/ftruncate → 상태 제거
* rename → 상태 이동
* release → 최종 평가 후 상태 제거

6. 메모리 제한
* PID당 추적 파일 수 제한
* 파일당 미완성 블록 수 제한

7. 정책
* 엔트로피 단독 차단 X
* 확장자 변경, 파일 연산 통계, Stage 2 결과와 함께 판단

References
* Zainodin et al. (2022), JOIV, 6(4), 856-861
* Lyda & Hamrock (2007), IEEE Security & Privacy, 5(2), 40-45
"""

from __future__ import annotations

import math
import os
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Iterator, Tuple

from guardfs.common.config import (
    ENTROPY_ACCUMULATION_MAX_LIFETIME_SEC,
    ENTROPY_ACCUMULATION_SIZE,
    ENTROPY_ACCUMULATION_WINDOW_SEC,
    ENTROPY_HEADER_SIZE,
    ENTROPY_MAX_BLOCKS_PER_FILE,
    ENTROPY_MAX_FILES_PER_PID,
    ENTROPY_MIN_SAMPLE_SIZE,
    ENTROPY_SHORT_SAMPLE_THRESHOLD,
    ENTROPY_THRESHOLD,
)

FileKey = Tuple[int, str]
BlockKey = Tuple[int, str, int]

# Shannon 엔트로피 탐지 임계값
# 근거: Zainodin et al. (2022) Table III - 256바이트 기준 WannaCry 7.166
# ZIP/7z 7.002로 분포, 7.0을 경계값으로 사용

# 논문 방식: 첫 256바이트 기준으로 엔트로피 계산
# 근거: Zainodin et al. (2022) - 파일 헤더(256바이트) 분석 방식


@dataclass(frozen=True)
class EntropyResult:
    """엔트로피 평가 결과"""

    entropy: float
    threshold: float
    block_index: int
    sample_size: int
    is_short_sample: bool

    @property
    def is_suspicious(self) -> bool:
        return self.entropy >= self.threshold


def shannon_entropy(data: bytes) -> float:
    """
    바이트 데이터의 Shannon 엔트로피 계산

    반환값 범위:
        0.0: 모든 바이트가 동일한 데이터
        8.0: 바이트 값이 균등하게 분포한 데이터

    수시:
        H = -sum(p(x) * log2(p(x)))
    """

    if not data:
        return 0.0

    frequencies = [0] * 256

    for value in data:
        frequencies[value] += 1

    size = len(data)
    entropy = 0.0

    for count in frequencies:
        if count:
            probability = count / size
            entropy -= probability * math.log2(probability)

    return entropy


class _EntropyBlock:
    """하나의 고정 크기 엔트로피 검사 블록에 대한 누적 상태"""

    __slots__ = (
        "data",
        "present",
        "present_count",
        "first_seen",
        "last_seen",
    )

    def __init__(self, capacity: int) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be greater than zero")

        # 실제 write 데이터를 offset 위치에 맞춰 저장한다.
        self.data = bytearray(capacity)

        # 각 위치의 데이터가 수집되었는지를 0 또는 1로 기록한다.
        self.present = bytearray(capacity)

        # 중복 write를 제외하고 실제로 확보된 바이트 수다.
        self.present_count = 0

        # 이 블록에 첫 write가 들어온 시각이다.
        self.first_seen: float | None = None

        # 이 블록에 마지막 write가 들어온 시각이다.
        self.last_seen: float | None = None

    @property
    def capacity(self) -> int:
        """블록 전체 크기 반환"""

        return len(self.data)

    def add(
        self,
        offset: int,
        data: bytes,
        now: float | None = None,
    ) -> int:
        """
        - 블록 내부 offset에 write 데이터를 기록
        - 이미 수집된 위치를 다시 쓰면 데이터를 덮어쓰지만 present_count는 증가 X
        - 반환값은 이번 호출로 새롭게 확보된 바이트 수
        """

        if not data:
            return 0

        if offset < 0 or offset >= self.capacity:
            return 0

        if now is None:
            now = time.monotonic()

        if self.first_seen is None:
            self.first_seen = now

        self.last_seen = now

        writable_size = min(
            len(data),
            self.capacity - offset,
        )

        newly_present = 0

        for index in range(writable_size):
            position = offset + index
            self.data[position] = data[index]

            if not self.present[position]:
                self.present[position] = 1
                self.present_count += 1
                newly_present += 1

        return newly_present

    def has_prefix(self, size: int) -> bool:
        """블록 offset 0부터 size 바이트까지 모두 수집되었는지 확인"""

        if size <= 0 or size > self.capacity:
            return False

        return all(self.present[:size])

    def contiguous_prefix_size(self) -> int:
        """블록 offset 0부터 연속해서 확보된 바이트 수를 반환"""

        for position, is_present in enumerate(self.present):
            if not is_present:
                return position

        return self.capacity

    def prefix(self, size: int) -> bytes:
        """블록 offset 0부터 지정한 크기만큼 데이터를 반환"""

        if size < 0 or size > self.capacity:
            raise ValueError("size must be between 0 and block capacity")

        return bytes(self.data[:size])

    def is_complete(self) -> bool:
        """블록의 모든 위치가 수집되었는지 확인"""

        return self.present_count == self.capacity

    def is_expired(
        self,
        now: float,
        inactivity_timeout_sec: float,
        max_lifetime_sec: float,
    ) -> bool:
        """
        누적 상태의 만료 여부를 확인

        조건:
        - 마지막 write 이후 비활성 제한 시간 초과
        - 첫 write 이후 전체 수명 제한 시간 초과
        """

        if inactivity_timeout_sec <= 0:
            raise ValueError("inactivity_timeout_sec must be greater than zero")

        if max_lifetime_sec <= 0:
            raise ValueError("max_lifetime_sec must be greater than zero")

        if self.first_seen is None or self.last_seen is None:
            return False

        inactive_too_long = now - self.last_seen > inactivity_timeout_sec
        lifetime_too_long = now - self.first_seen > max_lifetime_sec

        return inactive_too_long or lifetime_too_long

    def reset(self) -> None:
        """블록에 누적된 데이터와 시간 정보를 모두 초기화"""

        self.data[:] = b"\x00" * self.capacity
        self.present[:] = b"\x00" * self.capacity
        self.present_count = 0
        self.first_seen = None
        self.last_seen = None


class EntropyDetector:
    def __init__(
        self,
        threshold: float = ENTROPY_THRESHOLD,
        header_size: int = ENTROPY_HEADER_SIZE,
        accumulation_window_sec: float = ENTROPY_ACCUMULATION_WINDOW_SEC,
        accumulation_max_lifetime_sec: float = (ENTROPY_ACCUMULATION_MAX_LIFETIME_SEC),
        accumulation_size: int = ENTROPY_ACCUMULATION_SIZE,
        min_sample_size: int = ENTROPY_MIN_SAMPLE_SIZE,
        short_sample_threshold: float = ENTROPY_SHORT_SAMPLE_THRESHOLD,
        max_blocks_per_file: int = ENTROPY_MAX_BLOCKS_PER_FILE,
        max_files_per_pid: int = ENTROPY_MAX_FILES_PER_PID,
    ) -> None:

        self._validate_config(
            threshold=threshold,
            header_size=header_size,
            accumulation_window_sec=accumulation_window_sec,
            accumulation_max_lifetime_sec=accumulation_max_lifetime_sec,
            accumulation_size=accumulation_size,
            min_sample_size=min_sample_size,
            short_sample_threshold=short_sample_threshold,
            max_blocks_per_file=max_blocks_per_file,
            max_files_per_pid=max_files_per_pid,
        )

        self.threshold = threshold
        self.header_size = header_size
        self.block_size = header_size
        self.accumulation_size = accumulation_size
        self.accumulation_window_sec = accumulation_window_sec
        self.accumulation_max_lifetime_sec = accumulation_max_lifetime_sec
        self.min_sample_size = min_sample_size
        self.short_sample_threshold = short_sample_threshold
        self.max_blocks_per_file = max_blocks_per_file
        self.max_files_per_pid = max_files_per_pid

        # (pid, normalized_path, block_index) -> 블록 누적 상태
        self._blocks: dict[BlockKey, _EntropyBlock] = {}

        # PID -> 최근 접근한 파일 경로 순서
        self._pid_files: dict[
            int,
            OrderedDict[str, None],
        ] = {}

        # (pid, normalized_path) -> 추적 중인 블록 순서
        self._file_blocks: dict[
            FileKey,
            OrderedDict[int, None],
        ] = {}

    # ---------- 1. 설정 검증 ---------- #

    @staticmethod
    def _validate_config(
        threshold: float,
        header_size: int,
        accumulation_window_sec: float,
        accumulation_max_lifetime_sec: float,
        accumulation_size: int,
        min_sample_size: int,
        short_sample_threshold: float,
        max_blocks_per_file: int,
        max_files_per_pid: int,
    ) -> None:
        if not 0.0 <= threshold <= 8.0:
            raise ValueError("threshold must be between 0.0 and 8.0")

        if header_size <= 0:
            raise ValueError("header_size must be greater than zero")

        if accumulation_size <= 0:
            raise ValueError("accumulation_size must be greater than zero")

        if accumulation_size != header_size:
            raise ValueError("accumulation_size must equal header_size")

        if min_sample_size <= 0:
            raise ValueError("min_sample_size must be greater than zero")

        if min_sample_size >= accumulation_size:
            raise ValueError("min_sample_size must be smaller than accumulation_size")

        if not 0.0 <= short_sample_threshold <= 8.0:
            raise ValueError("short_sample_threshold must be between 0.0 and 8.0")

        if max_blocks_per_file <= 0:
            raise ValueError("max_blocks_per_file must be greater than zero")

        if max_files_per_pid <= 0:
            raise ValueError("max_files_per_pid must be greater than zero")

        if accumulation_window_sec <= 0:
            raise ValueError("accumulation_window_sec must be greater than zero")

        if accumulation_max_lifetime_sec <= 0:
            raise ValueError("accumulation_max_lifetime_sec must be greater than zero")

        if accumulation_max_lifetime_sec < accumulation_window_sec:
            raise ValueError(
                "accumulation_max_lifetime_sec must be greater than "
                "or equal to accumulation_window_sec"
            )

    # ---------- 2. 경로 & key 생성 ---------- #

    @staticmethod
    def _normalize_path(path: str) -> str:
        return os.path.realpath(path or "")

    @classmethod
    def _file_key(
        cls,
        pid: int,
        path: str,
    ) -> FileKey:
        return (
            pid,
            cls._normalize_path(path),
        )

    @classmethod
    def _block_key(
        cls,
        pid: int,
        path: str,
        block_index: int,
    ) -> BlockKey:
        file_key = cls._file_key(pid, path)

        return (
            file_key[0],
            file_key[1],
            block_index,
        )

    # ---------- 3. 파일 및 블록 등록 ---------- #

    def _register_file(
        self,
        pid: int,
        path: str,
    ) -> None:
        normalized_path = self._normalize_path(path)

        pid_files = self._pid_files.setdefault(
            pid,
            OrderedDict(),
        )

        if normalized_path in pid_files:
            pid_files.move_to_end(normalized_path)
            return

        while len(pid_files) >= self.max_files_per_pid:
            oldest_path = next(iter(pid_files))

            self._discard_file(
                pid=pid,
                normalized_path=oldest_path,
            )

            pid_files = self._pid_files.setdefault(
                pid,
                OrderedDict(),
            )

        pid_files[normalized_path] = None

    def _register_block(
        self,
        pid: int,
        path: str,
        block_index: int,
    ) -> bool:
        file_key = self._file_key(pid, path)

        blocks = self._file_blocks.get(file_key)

        if blocks is None:
            blocks = OrderedDict()
            self._file_blocks[file_key] = blocks

        if block_index in blocks:
            blocks.move_to_end(block_index)
            return True

        if len(blocks) >= self.max_blocks_per_file:
            return False

        blocks[block_index] = None
        return True

    def _get_or_create_block(
        self,
        pid: int,
        path: str,
        block_index: int,
    ) -> _EntropyBlock | None:
        block_key = self._block_key(
            pid=pid,
            path=path,
            block_index=block_index,
        )

        existing_block = self._blocks.get(block_key)

        if existing_block is not None:
            self._register_file(pid, path)
            self._register_block(pid, path, block_index)
            return existing_block

        self._register_file(pid, path)

        registered = self._register_block(
            pid=pid,
            path=path,
            block_index=block_index,
        )

        if not registered:
            return None

        block = _EntropyBlock(
            capacity=self.block_size,
        )

        self._blocks[block_key] = block

        return block

    # ---------- 4. 상태 제거와 자원 정리 ---------- #

    def _remove_block(
        self,
        block_key: BlockKey,
    ) -> None:
        pid, normalized_path, block_index = block_key

        self._blocks.pop(block_key, None)

        file_key = (
            pid,
            normalized_path,
        )

        file_blocks = self._file_blocks.get(file_key)

        if file_blocks is None:
            return

        file_blocks.pop(block_index, None)

        if file_blocks:
            return

        self._file_blocks.pop(file_key, None)

        pid_files = self._pid_files.get(pid)

        if pid_files is None:
            return

        pid_files.pop(normalized_path, None)

        if not pid_files:
            self._pid_files.pop(pid, None)

    def _discard_file(
        self,
        pid: int,
        normalized_path: str,
    ) -> None:
        file_key = (
            pid,
            normalized_path,
        )

        file_blocks = self._file_blocks.pop(
            file_key,
            OrderedDict(),
        )

        for block_index in list(file_blocks):
            block_key = (
                pid,
                normalized_path,
                block_index,
            )
            self._blocks.pop(block_key, None)

        pid_files = self._pid_files.get(pid)

        if pid_files is None:
            return

        pid_files.pop(normalized_path, None)

        if not pid_files:
            self._pid_files.pop(pid, None)

    def _cleanup_expired(
        self,
        now: float,
    ) -> None:
        """비활성 시간 또는 전체 수명을 초과한 블록을 제거한다."""

        expired_keys = [
            block_key
            for block_key, block in self._blocks.items()
            if block.is_expired(
                now=now,
                inactivity_timeout_sec=self.accumulation_window_sec,
                max_lifetime_sec=self.accumulation_max_lifetime_sec,
            )
        ]

        for block_key in expired_keys:
            self._remove_block(block_key)

    # ---------- 5. write 데이터를 블록 단위로 분할 ---------- #

    def _split_write_into_blocks(
        self,
        file_offset: int,
        data: bytes,
    ) -> Iterator[tuple[int, int, bytes]]:
        if file_offset < 0 or not data:
            return

        cursor = 0

        while cursor < len(data):
            absolute_offset = file_offset + cursor
            block_index = absolute_offset // self.block_size
            block_offset = absolute_offset % self.block_size

            writable_size = min(
                len(data) - cursor,
                self.block_size - block_offset,
            )

            yield (
                block_index,
                block_offset,
                data[cursor : cursor + writable_size],
            )

            cursor += writable_size

    def _accumulate_write(
        self,
        pid: int,
        path: str,
        file_offset: int,
        data: bytes,
        now: float,
    ) -> list[tuple[int, _EntropyBlock]]:
        completed_blocks: list[tuple[int, _EntropyBlock]] = []

        for (
            block_index,
            block_offset,
            block_data,
        ) in self._split_write_into_blocks(
            file_offset=file_offset,
            data=data,
        ):
            block = self._get_or_create_block(
                pid=pid,
                path=path,
                block_index=block_index,
            )

            if block is None:
                continue

            block.add(
                offset=block_offset,
                data=block_data,
                now=now,
            )

            if not block.is_complete():
                continue

            completed_blocks.append(
                (
                    block_index,
                    block,
                )
            )

            block_key = self._block_key(
                pid=pid,
                path=path,
                block_index=block_index,
            )

            self._remove_block(block_key)

        return completed_blocks

    # ---------- 6. 완성된 일반 블록 평가 ---------- #

    def _evaluate_complete_block(
        self,
        block_index: int,
        block: _EntropyBlock,
    ) -> EntropyResult:
        sample = block.prefix(self.block_size)
        entropy = shannon_entropy(sample)

        return EntropyResult(
            entropy=entropy,
            threshold=self.threshold,
            block_index=block_index,
            sample_size=len(sample),
            is_short_sample=False,
        )

    def _evaluate_write(
        self,
        ev,
    ) -> EntropyResult | None:
        sample_data = getattr(
            ev,
            "sample_data",
            None,
        )

        if not sample_data:
            return None

        if ev.off < 0:
            return None

        now = time.monotonic()

        self._cleanup_expired(now)

        completed_blocks = self._accumulate_write(
            pid=ev.pid,
            path=ev.path,
            file_offset=ev.off,
            data=sample_data,
            now=now,
        )

        if not completed_blocks:
            return None

        results = [
            self._evaluate_complete_block(
                block_index=block_index,
                block=block,
            )
            for block_index, block in completed_blocks
        ]

        return max(
            results,
            key=lambda result: result.entropy,
        )

    # ---------- 7. 256바이트 미만 파일 최종 평가 ---------- #

    def finalize(
        self,
        pid: int,
        path: str,
        file_size: int | None,
    ) -> EntropyResult | None:
        normalized_path = self._normalize_path(path)

        block_key = (
            pid,
            normalized_path,
            0,
        )

        block = self._blocks.get(block_key)

        try:
            if block is None:
                return None

            if file_size is None:
                return None

            if file_size < self.min_sample_size:
                return None

            if file_size >= self.block_size:
                return None

            contiguous_size = block.contiguous_prefix_size()

            if contiguous_size < file_size:
                return None

            sample = block.prefix(file_size)
            entropy = shannon_entropy(sample)

            return EntropyResult(
                entropy=entropy,
                threshold=self.short_sample_threshold,
                block_index=0,
                sample_size=len(sample),
                is_short_sample=True,
            )

        finally:
            self._discard_file(
                pid=pid,
                normalized_path=normalized_path,
            )

    # ---------- 8. 파일 생명주기 관리 ---------- #

    def discard(
        self,
        pid: int,
        path: str,
    ) -> None:
        """PID와 파일 경로에 대응하는 누적 상태를 제거"""

        normalized_path = self._normalize_path(path)

        self._discard_file(
            pid=pid,
            normalized_path=normalized_path,
        )

    def move(
        self,
        pid: int,
        old_path: str,
        new_path: str,
    ) -> None:
        """rename된 파일의 엔트로피 누적 상태를 새 경로로 이동"""

        old_normalized_path = self._normalize_path(old_path)
        new_normalized_path = self._normalize_path(new_path)

        if old_normalized_path == new_normalized_path:
            return

        old_file_key: FileKey = (
            pid,
            old_normalized_path,
        )
        new_file_key: FileKey = (
            pid,
            new_normalized_path,
        )

        old_blocks = self._file_blocks.pop(
            old_file_key,
            None,
        )

        if old_blocks is None:
            return

        # 새 경로에 기존 누적 상태가 있으면 rename 원본 상태로 교체
        self._discard_file(
            pid=pid,
            normalized_path=new_normalized_path,
        )

        moved_blocks: OrderedDict[int, None] = OrderedDict()

        for block_index in old_blocks:
            old_block_key: BlockKey = (
                pid,
                old_normalized_path,
                block_index,
            )
            new_block_key: BlockKey = (
                pid,
                new_normalized_path,
                block_index,
            )

            block = self._blocks.pop(
                old_block_key,
                None,
            )

            if block is None:
                continue

            self._blocks[new_block_key] = block
            moved_blocks[block_index] = None

        pid_files = self._pid_files.get(pid)

        if pid_files is not None:
            pid_files.pop(old_normalized_path, None)

        if not moved_blocks:
            if pid_files is not None and not pid_files:
                self._pid_files.pop(pid, None)

            return

        self._file_blocks[new_file_key] = moved_blocks

        pid_files = self._pid_files.setdefault(
            pid,
            OrderedDict(),
        )
        pid_files[new_normalized_path] = None

    # ---------- 9. 외부 이벤트 진입점 ---------- #

    def check(self, ev) -> bool:
        """
        write 이벤트에서 buf의 첫 256바이트 Shannon 엔트로피를 계산
        Zainodin et al. (2022) 256바이트 헤더 분석 방식을 실시간 FUSE 환경에 적용
        임계값 7.0 초과 시 True 반환
        """

        if not getattr(ev, "applied", True):
            return False

        result: EntropyResult | None

        if ev.op == "write":
            # 기존 조각별 entropy가 남아 있다면 제거하고
            # 누적 블록 entropy로 교체한다.
            ev.entropy = None
            result = self._evaluate_write(ev)

        elif ev.op == "release":
            result = self.finalize(
                pid=ev.pid,
                path=ev.path,
                file_size=ev.size,
            )

        else:
            return False

        if result is None:
            return False

        ev.entropy = result.entropy

        return result.is_suspicious
