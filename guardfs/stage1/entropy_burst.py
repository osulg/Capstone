"""
PID별 High-Entropy Burst 탐지

단일 고엔트로피 write를 랜섬웨어로 확정하지 않고,
같은 PID가 짧은 시간 동안 여러 파일에 반복적으로
고엔트로피 데이터를 쓰는 패턴을 집계
"""

from __future__ import annotations

import os
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Deque


@dataclass(frozen=True)
class EntropyBurstEvent:
    """Burst 집계에 사용되는 하나의 고엔트로피 write"""

    timestamp: float
    path: str
    entropy: float
    written_bytes: int


@dataclass(frozen=True)
class EntropyBurstSnapshot:
    """특정 PID의 현재 Burst 통계"""

    pid: int
    window_sec: float
    high_entropy_writes: int
    high_entropy_files: int
    high_entropy_bytes: int
    mean_entropy: float
    max_entropy: float

    @property
    def is_burst(self) -> bool:
        return False


class _BurstState:
    """하나의 PID에 대한 시간창 내 Burst 상태"""

    __slots__ = ("events", "last_seen")

    def __init__(self) -> None:
        self.events: Deque[EntropyBurstEvent] = deque()
        self.last_seen: float | None = None

    def add(self, event: EntropyBurstEvent) -> None:
        self.events.append(event)
        self.last_seen = event.timestamp

    def remove_expired(
        self,
        now: float,
        window_sec: float,
    ) -> None:
        cutoff = now - window_sec

        while self.events and self.events[0].timestamp < cutoff:
            self.events.popleft()

    def is_empty(self) -> bool:
        return not self.events

    def snapshot(
        self,
        pid: int,
        window_sec: float,
    ) -> EntropyBurstSnapshot:
        if not self.events:
            return EntropyBurstSnapshot(
                pid=pid,
                window_sec=window_sec,
                high_entropy_writes=0,
                high_entropy_files=0,
                high_entropy_bytes=0,
                mean_entropy=0.0,
                max_entropy=0.0,
            )

        entropies = [event.entropy for event in self.events]

        files = {event.path for event in self.events}

        return EntropyBurstSnapshot(
            pid=pid,
            window_sec=window_sec,
            high_entropy_writes=len(self.events),
            high_entropy_files=len(files),
            high_entropy_bytes=sum(event.written_bytes for event in self.events),
            mean_entropy=sum(entropies) / len(entropies),
            max_entropy=max(entropies),
        )


class EntropyBurstDetector:
    """
    PID별 High-Entropy Burst 탐지기

    - 이 클래스는 entropy를 직접 계산하지 않음
    - EntropyDetector.check()가 ev.entropy에 값을 기록한 뒤
      이 클래스가 해당 이벤트를 집계
    """

    def __init__(
        self,
        entropy_threshold: float = 7.0,
        window_sec: float = 5.0,
        min_writes: int = 5,
        min_files: int = 3,
        min_bytes: int = 1280,
        max_pids: int = 10000,
        observe_only: bool = True,
    ) -> None:
        self._validate_config(
            entropy_threshold=entropy_threshold,
            window_sec=window_sec,
            min_writes=min_writes,
            min_files=min_files,
            min_bytes=min_bytes,
            max_pids=max_pids,
        )

        self.entropy_threshold = entropy_threshold
        self.window_sec = window_sec
        self.min_writes = min_writes
        self.min_files = min_files
        self.min_bytes = min_bytes
        self.max_pids = max_pids

        # True이면 통계만 집계하고 suspicious 판정은 하지 않음
        # 초기 운영에서는 True로 두고 데이터를 수집하는 것을 권장
        self.observe_only = observe_only

        # pid -> Burst 상태
        self._states: OrderedDict[
            int,
            _BurstState,
        ] = OrderedDict()

    @staticmethod
    def _validate_config(
        entropy_threshold: float,
        window_sec: float,
        min_writes: int,
        min_files: int,
        min_bytes: int,
        max_pids: int,
    ) -> None:
        if not 0.0 <= entropy_threshold <= 8.0:
            raise ValueError("entropy_threshold must be between 0.0 and 8.0")

        if window_sec <= 0:
            raise ValueError("window_sec must be greater than zero")

        if min_writes <= 0:
            raise ValueError("min_writes must be greater than zero")

        if min_files <= 0:
            raise ValueError("min_files must be greater than zero")

        if min_bytes <= 0:
            raise ValueError("min_bytes must be greater than zero")

        if max_pids <= 0:
            raise ValueError("max_pids must be greater than zero")

    @staticmethod
    def _normalize_path(path: str) -> str:
        return os.path.realpath(path or "")

    def _get_or_create_state(
        self,
        pid: int,
    ) -> _BurstState:
        state = self._states.get(pid)

        if state is not None:
            self._states.move_to_end(pid)
            return state

        while len(self._states) >= self.max_pids:
            self._states.popitem(last=False)

        state = _BurstState()
        self._states[pid] = state

        return state

    def _cleanup(
        self,
        now: float,
    ) -> None:
        expired_pids: list[int] = []

        for pid, state in self._states.items():
            state.remove_expired(
                now=now,
                window_sec=self.window_sec,
            )

            if state.is_empty():
                expired_pids.append(pid)

        for pid in expired_pids:
            self._states.pop(pid, None)

    def _is_high_entropy_event(self, ev) -> bool:
        if getattr(ev, "op", None) != "write":
            return False

        if not getattr(ev, "applied", True):
            return False

        entropy = getattr(ev, "entropy", None)

        if entropy is None:
            return False

        return entropy >= self.entropy_threshold

    def _make_event(
        self,
        ev,
        now: float,
    ) -> EntropyBurstEvent:
        sample_data = getattr(
            ev,
            "sample_data",
            None,
        )

        # Burst byte 수는 실제 write 요청 크기를 사용
        written_bytes = int(getattr(ev, "size", 0) or 0)

        if written_bytes <= 0 and sample_data:
            written_bytes = len(sample_data)

        return EntropyBurstEvent(
            timestamp=now,
            path=self._normalize_path(getattr(ev, "path", "")),
            entropy=float(ev.entropy),
            written_bytes=written_bytes,
        )

    def _matches_policy(
        self,
        snapshot: EntropyBurstSnapshot,
    ) -> bool:
        return (
            snapshot.high_entropy_writes >= self.min_writes
            and snapshot.high_entropy_files >= self.min_files
            and snapshot.high_entropy_bytes >= self.min_bytes
        )

    def observe(
        self,
        ev,
    ) -> bool:
        """
        이벤트를 관찰하고 Burst 여부를 반환

        observe_only=True이면 통계만 갱신하고 항상 False를 반환
        """

        now = time.monotonic()

        self._cleanup(now)

        if not self._is_high_entropy_event(ev):
            return False

        pid = int(getattr(ev, "pid", -1))

        if pid <= 0:
            return False

        state = self._get_or_create_state(pid)

        state.add(
            self._make_event(
                ev=ev,
                now=now,
            )
        )

        snapshot = state.snapshot(
            pid=pid,
            window_sec=self.window_sec,
        )

        if self.observe_only:
            return False

        return self._matches_policy(snapshot)

    def snapshot(
        self,
        pid: int,
    ) -> EntropyBurstSnapshot:
        """특정 PID의 현재 Burst 통계를 반환"""

        now = time.monotonic()
        self._cleanup(now)

        state = self._states.get(pid)

        if state is None:
            return EntropyBurstSnapshot(
                pid=pid,
                window_sec=self.window_sec,
                high_entropy_writes=0,
                high_entropy_files=0,
                high_entropy_bytes=0,
                mean_entropy=0.0,
                max_entropy=0.0,
            )

        self._states.move_to_end(pid)

        return state.snapshot(
            pid=pid,
            window_sec=self.window_sec,
        )

    def discard(
        self,
        pid: int,
    ) -> None:
        """PID 종료 또는 명시적 정리 시 Burst 상태를 제거"""

        self._states.pop(pid, None)

    def clear(self) -> None:
        """모든 PID의 Burst 상태를 제거"""

        self._states.clear()
