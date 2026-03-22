"""
HoneypotDetector
- honeypot 디렉토리 안의 파일에 open/read/write/lookup/rename/unlink 접근이 발생하면 탐지
- 정상 프로세스가 honeypot 파일에 접근할 이유가 없으므로 즉시 의심 판정
"""

import os


class HoneypotDetector:
    def __init__(self, honeypot_dir: str):
        # honeypot 디렉토리의 절대 경로를 정규화해서 저장
        self._honeypot_dir = os.path.realpath(honeypot_dir)

    def check(self, ev) -> bool:
        if ev.op not in ("open", "read", "write", "lookup", "rename", "unlink"):
            return False

        # 현재 경로 확인
        target = os.path.realpath(ev.path)
        if target.startswith(self._honeypot_dir + os.sep) or target == self._honeypot_dir:
            return True

        # rename의 목적지 경로도 확인
        if getattr(ev, "new_path", None):
            new_target = os.path.realpath(ev.new_path)
            if new_target.startswith(self._honeypot_dir + os.sep) or new_target == self._honeypot_dir:
                return True

        return False