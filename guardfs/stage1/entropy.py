"""
EntropyDetector
- write 이벤트에서 파일에 쓰이는 데이터의 Shannon 엔트로피를 계산
- Zainodin et al. (2022)의 256바이트 헤더 분석 방식을 실시간 FUSE 환경에 적용
- 엔트로피 >= 7.0 이상이면 암호화/난독화된 악성 파일로 탐지
- 근거: Zainodin et al. (2022), JOIV Vol.6(4), pp.856-861
         Lyda & Hamrock (2007), IEEE Security & Privacy, Vol.5(2), pp.40-45
"""

import math

# Shannon 엔트로피 탐지 임계값
# 근거: Zainodin et al. (2022) Table III - 256바이트 기준 WannaCry 7.166,
#        ZIP/7z 7.002로 분포, 7.0을 경계값으로 사용
ENTROPY_THRESHOLD = 7.0

# 논문 방식: 첫 256바이트 기준으로 엔트로피 계산
# 근거: Zainodin et al. (2022) - 파일 헤더(256바이트) 분석 방식
HEADER_SIZE = 256


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


class EntropyDetector:
    def __init__(self, threshold: float = ENTROPY_THRESHOLD, header_size: int = HEADER_SIZE):
        self.threshold = threshold
        self.header_size = header_size

    def check(self, ev) -> bool:
        """
        write 이벤트에서 buf의 첫 256바이트 Shannon 엔트로피를 계산
        Zainodin et al. (2022) 256바이트 헤더 분석 방식을 실시간 FUSE 환경에 적용
        임계값 7.0 초과 시 True 반환
        """
        if ev.op != "write":
            return False

        # 256바이트 미만은 분석 의미 없음 (논문 방식 동일)
        if ev.size < self.header_size:
            return False

        if ev.entropy is None:
            return False

        return ev.entropy >= self.threshold
