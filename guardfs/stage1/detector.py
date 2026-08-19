"""
Stage1Detector
- 세 가지 탐지기(Honeypot / 확장자 변경 / Entropy)를 통합
- 하나라도 탐지되면 True와 reason만 반환
- mark_suspect 호출은 stats_collector에서 처리
"""

from .honeypot import HoneypotDetector
from .ext_change import ExtChangeDetector
from .entropy import EntropyDetector


class Stage1Detector:
    def __init__(self, honeypot_dir: str):
        self._detectors = [
            HoneypotDetector(honeypot_dir),
            ExtChangeDetector(),
            EntropyDetector(),
        ]

    async def check(self, ev):
        """
        이벤트를 세 탐지기에 순서대로 넘긴다.
        하나라도 True를 반환하면 (True, reason)을 반환한다.
        """
        for detector in self._detectors:
            if detector.check(ev):
                reason = detector.__class__.__name__
                entropy_str = f"{ev.entropy:.4f}" if ev.entropy is not None else "N/A"

                print(
                    f"[STAGE1] pid={ev.pid} op={ev.op} "
                    f"path={ev.path} entropy={entropy_str} reason={reason}"
                )

                return True, reason

        return False, None