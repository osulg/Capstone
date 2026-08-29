"""
EntropyDetector
- write 이벤트에서 파일에 쓰이는 데이터의 Shannon 엔트로피를 계산
- Zainodin et al. (2022)의 256바이트 헤더 분석 방식을 실시간 FUSE 환경에 적용
- 엔트로피 >= 7.0 이상이면 암호화/난독화된 악성 파일로 탐지
- 근거: Zainodin et al. (2022), JOIV Vol.6(4), pp.856-861
        Lyda & Hamrock (2007), IEEE Security & Privacy, Vol.5(2), pp.40-45
"""

import math
import os
import time

from guardfs.common.config import (
    ENTROPY_ACCUMULATION_SIZE,
    ENTROPY_ACCUMULATION_WINDOW_SEC,
    ENTROPY_HEADER_SIZE,
    ENTROPY_THRESHOLD,
)

# Shannon 엔트로피 탐지 임계값
# 근거: Zainodin et al. (2022) Table III - 256바이트 기준 WannaCry 7.166
# ZIP/7z 7.002로 분포, 7.0을 경계값으로 사용

# 논문 방식: 첫 256바이트 기준으로 엔트로피 계산
# 근거: Zainodin et al. (2022) - 파일 헤더(256바이트) 분석 방식


def shannon_entropy(data: bytes) -> float:
    """
    바이트 데이터의 Shannon 엔트로피 계산
    반환값 범위: 0.0 (완전 규칙적) ~ 8.0 (완전 무작위)
    수식: H = -sum(p(x) * log2(p(x)))
    """

    if not data:
        return 0.0

    freq = [0] * 256
    for b in data:
        freq[b] += 1

    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)

    return ent


class _EntropyAccumulator:
    """하나의 PID와 파일에 대한 작은 write 누적 상태"""

    __slots__ = (
        "total_size",  # 시간 창 안에서 누적된 write 크기
        "weighted_entropy_sum",  # entropy x write 크기의 합
        "high_entropy_size",  # entropy가 threshold 이상인 write들의 크기의 합
        "last_seen",  # 마지막 이벤트가 발생한 monotonic 시간
    )

    def __init__(self):
        self.total_size = 0
        self.weighted_entropy_sum = 0.0
        self.high_entropy_size = 0
        self.last_seen = 0.0

    def reset(self):
        self.total_size = 0
        self.weighted_entropy_sum = 0.0
        self.high_entropy_size = 0
        self.last_seen = 0.0


class EntropyDetector:
    def __init__(
        self,
        threshold: float = ENTROPY_THRESHOLD,
        header_size: int = ENTROPY_HEADER_SIZE,
        accumulation_window_sec: float = ENTROPY_ACCUMULATION_WINDOW_SEC,
        accumulation_size: int = ENTROPY_ACCUMULATION_SIZE,
    ):
        self.threshold = threshold
        self.header_size = header_size
        self.accumulation_window_sec = accumulation_window_sec
        self.accumulation_size = accumulation_size

        # (PID, 실제 파일 경로)별 누적 상태
        self._accumulators = {}

    def _key(self, ev):
        """서로 다른 PID와 파일의 write가 섞이지 않도록 함"""
        path = os.path.realpath(ev.path or "")

        return ev.pid, path

    def _get_accumulator(self, key, now: float):
        state = self._accumulators.get(key)

        if state is None:
            state = _EntropyAccumulator()
            self._accumulators[key] = state

            return state

        # 시간 창을 초과하면 과거 write를 폐기
        if now - state.last_seen > self.accumulation_window_sec:
            state.reset()

        return state

    def _cleanup_expired(self, now: float):
        """오래된 PID·파일 상태가 계속 메모리에 남지 않도록 정리"""
        expired_keys = [
            key
            for key, state in self._accumulators.items()
            if now - state.last_seen > self.accumulation_window_sec
        ]

        for key in expired_keys:
            self._accumulators.pop(key, None)

    def _is_high_entropy(self, entropy):
        return entropy is not None and entropy >= self.threshold

    def check(self, ev) -> bool:
        """
        write 이벤트에서 buf의 첫 256바이트 Shannon 엔트로피를 계산
        Zainodin et al. (2022) 256바이트 헤더 분석 방식을 실시간 FUSE 환경에 적용
        임계값 7.0 초과 시 True 반환
        """

        if ev.op != "write":
            return False

        if ev.size <= 0:
            return False

        if ev.entropy is None:
            return False

        now = time.monotonic()
        self._cleanup_expired(now)

        # 단일 대형 write는 기존 규칙을 그대로 적용
        if ev.size >= self.header_size:
            self._accumulators.pop(self._key(ev), None)
            return ev.entropy >= self.threshold

        # 작은 write는 PID와 파일별로 누적
        key = self._key(ev)
        state = self._get_accumulator(key, now)

        state.total_size += ev.size
        state.weighted_entropy_sum += ev.entropy * ev.size
        state.last_seen = now

        if self._is_high_entropy(ev.entropy):
            state.high_entropy_size += ev.size

        # 누적 크기가 기준보다 작으면 아직 판단하지 않는다.
        if state.total_size < self.accumulation_size:
            return False

        weighted_entropy = state.weighted_entropy_sum / state.total_size

        # 전체 누적 데이터의 평균 entropy와
        # 고엔트로피 데이터 비중을 모두 확인한다.
        high_entropy_ratio = state.high_entropy_size / state.total_size

        detected = weighted_entropy >= self.threshold and high_entropy_ratio >= 0.75

        self._accumulators.pop(key, None)

        return detected
