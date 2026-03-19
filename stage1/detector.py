"""
Stage1Detector
- 세 가지 탐지기(Honeypot / 확장자 변경 / 민감 경로)를 통합
- 하나라도 탐지되면 ops.mark_suspect(pid) 호출 → 2단계로 escalate
- stats_collector에서 분리
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

    async def check(self, ev, ops) -> bool:
        """
        이벤트를 세 탐지기에 순서대로 넘긴다.
        하나라도 True를 반환하면 즉시 mark_suspect 호출 후 True 반환.
        """
        for detector in self._detectors:
            if detector.check(ev):
                reason = detector.__class__.__name__
                print(
                    f"[STAGE1] pid={ev.pid} op={ev.op} "
                    f"path={ev.path} reason={reason}"
                )
                await ops.mark_suspect(ev.pid)
                return True
        return False
