"""
Stage1Detector

역할:
- HoneypotDetector, ExtChangeDetector, EntropyDetector 통합
- 일반 이벤트에 대한 Stage 1 탐지 수행
- 탐지 여부와 탐지기 이름 반환
"""

from .entropy import EntropyDetector
from .ext_change import ExtChangeDetector
from .honeypot import HoneypotDetector


class Stage1Detector:
    """GuardFS의 Stage 1 탐지기를 통합하여 실행"""

    def __init__(self, honeypot_dir: str):
        self.honeypot = HoneypotDetector(honeypot_dir)
        self.ext_change = ExtChangeDetector()
        self.entropy = EntropyDetector()

        # 먼저 탐지된 탐지기의 결과를 최종 탐지 이유로 사용
        self._detectors = [
            self.honeypot,
            self.ext_change,
            self.entropy,
        ]

    def precheck(self, ev):
        """
        실제 파일 연산 전에 차단할 강한 위험 신호 검사

        즉시 차단 대상:
        - 허니팟 경로 접근
        - 알려진 악성 확장자로 rename
        - 의심스러운 이중 확장자로 rename

        알 수 없는 확장자 변경 혹은 고엔트로피 write처럼
        누적 판단이 필요한 약한 신호는 차단 대상 아님
        """

        if self.honeypot.check(ev):
            return True, "HoneypotDetector"

        if self.ext_change.check_immediate(ev):
            return True, "ExtChangeDetector"

        return False, None

    def update_lifecycle(self, ev) -> None:
        """성공한 파일 연산에 따라 엔트로피 누적 상태를 정리"""

        if not getattr(ev, "applied", True):
            return

        if ev.op in (
            "unlink",
            "truncate",
            "ftruncate",
        ):
            self.entropy.discard(
                pid=ev.pid,
                path=ev.path,
            )

        elif ev.op == "rename" and ev.new_path:
            self.entropy.move(
                pid=ev.pid,
                old_path=ev.path,
                new_path=ev.new_path,
            )

    async def check(self, ev):
        """
        이벤트를 각 Stage 1 탐지기에 순서대로 전달

        하나의 탐지기라도 True를 반환하면:
            (True, 탐지기 클래스 이름)

        모든 탐지기가 False를 반환하면:
            (False, None)

        """

        for detector in self._detectors:
            if detector.check(ev):
                reason = detector.__class__.__name__

                entropy_str = f"{ev.entropy:.4f}" if ev.entropy is not None else "N/A"

                print(
                    f"[STAGE1] pid={ev.pid} "
                    f"op={ev.op} "
                    f"path={ev.path} "
                    f"entropy={entropy_str} "
                    f"reason={reason}"
                )

                return True, reason

        return False, None
