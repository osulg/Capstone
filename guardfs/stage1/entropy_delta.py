"""
EntropyDeltaResult

같은 파일 offset의 write 전·후 데이터를 비교해 엔트로피 변화량을 계산

정책 흐름:
    H_before = write 이전 원본 데이터의 Shannon entropy
    H_after  = write 데이터의 Shannon entropy
    delta    = H_after - H_before

- 원본 파일이 일반 텍스트이고 write 데이터가 암호화 데이터인 경우 delta가 크게 증가 가능
- ZIP, JPEG, MP4처럼 원래부터 엔트로피가 높은 파일
    - delta가 작아 단순 H >= 7.0 정책보다 오탐을 줄이는 데 도움을 줄 수 있음

정책:
    - 최소 샘플 크기 미만의 write는 평가하지 않음
    - 원본 데이터를 읽지 못한 이벤트는 평가하지 않음
    - 초기에는 observe_only 모드로 로그와 통계만 수집
    - threshold는 실제 정상·랜섬웨어 데이터 수집 후 조정
    - 이 정책은 기존 EntropyDetector를 대체하지 않고 보조 신호로 사용
"""

from __future__ import annotations

from dataclasses import dataclass

from guardfs.common.config import (
    ENTROPY_DELTA_MIN_SAMPLE_SIZE,
    ENTROPY_DELTA_OBSERVE_ONLY,
    ENTROPY_DELTA_SAMPLE_SIZE,
    ENTROPY_DELTA_THRESHOLD,
)

from .entropy import shannon_entropy


@dataclass(frozen=True)
class EntropyDeltaResult:
    before_entropy: float
    after_entropy: float
    delta: float
    threshold: float
    sample_size: int
    is_suspicious: bool


class EntropyDeltaDetector:
    def __init__(
        self,
        threshold: float = ENTROPY_DELTA_THRESHOLD,
        sample_size: int = ENTROPY_DELTA_SAMPLE_SIZE,
        min_sample_size: int = ENTROPY_DELTA_MIN_SAMPLE_SIZE,
        observe_only: bool = ENTROPY_DELTA_OBSERVE_ONLY,
    ) -> None:
        if not 0.0 <= threshold <= 8.0:
            raise ValueError("threshold must be between 0.0 and 8.0")

        if sample_size <= 0:
            raise ValueError("sample_size must be greater than zero")

        if min_sample_size <= 0:
            raise ValueError("min_sample_size must be greater than zero")

        if min_sample_size > sample_size:
            raise ValueError("min_sample_size must not exceed sample_size")

        self.threshold = threshold
        self.sample_size = sample_size
        self.min_sample_size = min_sample_size
        self.observe_only = observe_only

    def check(self, ev) -> EntropyDeltaResult | None:
        if not getattr(ev, "applied", True):
            return None

        if getattr(ev, "op", None) != "write":
            return None

        write_data = getattr(ev, "sample_data", None)
        original_data = getattr(ev, "original_data", None)

        if not write_data or not original_data:
            return None

        size = min(
            len(write_data),
            len(original_data),
            self.sample_size,
        )

        if size < self.min_sample_size:
            return None

        before_entropy = shannon_entropy(bytes(original_data[:size]))
        after_entropy = shannon_entropy(bytes(write_data[:size]))
        delta = after_entropy - before_entropy

        result = EntropyDeltaResult(
            before_entropy=before_entropy,
            after_entropy=after_entropy,
            delta=delta,
            threshold=self.threshold,
            sample_size=size,
            is_suspicious=delta >= self.threshold,
        )

        # 로그와 통계에서 사용할 수 있도록 이벤트에 기록
        ev.entropy_before = before_entropy
        ev.entropy_after = after_entropy
        ev.entropy_delta = delta

        return result
