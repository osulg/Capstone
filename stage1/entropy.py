"""
EntropyDetector
- Shannon 엔트로피 계산 및 탐지 담당
- 엔트로피 >= 7.0 이상이면 암호화/난독화된 악성 파일로 탐지
- 근거: Lyda & Hamrock (2007), IEEE Security & Privacy
"""
import math

ENTROPY_THRESHOLD = 7.0
MIN_BUFFER_SIZE = 128


def shannon_entropy(data: bytes) -> float:
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


class EntropyDetector:
    def __init__(self, threshold: float = ENTROPY_THRESHOLD):
        self.threshold = threshold

    def check(self, ev) -> bool:
        if ev.op != "write":
            return False
        if ev.size < MIN_BUFFER_SIZE:
            return False
        if ev.entropy is None:
            return False
        return ev.entropy >= self.threshold
