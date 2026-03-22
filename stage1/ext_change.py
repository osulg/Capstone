"""
ExtChangeDetector
- rename 이벤트에서 old_path → new_path 확장자를 비교
- 랜섬웨어/악성코드가 사용하는 확장자 블랙리스트에 해당하면 탐지
- 정상 확장자 → 알 수 없는 확장자로 변경되는 경우는 횟수 기반으로 탐지
"""

import os
import time

# 랜섬웨어 및 악성코드에서 자주 관찰되는 확장자 블랙리스트
SUSPICIOUS_EXTENSIONS = {
    ".locked", ".enc", ".encrypted", ".crypt", ".crypted",
    ".cryp1", ".cerber", ".zepto", ".locky", ".wnry",
    ".wncry", ".wncryt", ".petya", ".loki", ".sage",
    ".evil", ".malware", ".payload",
}

# 정상 확장자
NORMAL_EXTENSIONS = {
    ".txt", ".doc", ".docx", ".pdf", ".xls", ".xlsx",
    ".ppt", ".pptx", ".jpg", ".jpeg", ".png", ".gif",
    ".mp4", ".mp3", ".zip", ".tar", ".gz", ".py",
    ".js", ".html", ".css", ".json", ".xml", ".csv",
}


class ExtChangeDetector:
    def __init__(self, window_sec=10, threshold=5):
        self.window_sec = window_sec
        self.threshold = threshold
        self.history = {}  # pid -> timestamps

    def check(self, ev) -> bool:
        if ev.op != "rename" or not ev.new_path:
            return False

        old_ext = self._get_ext(ev.path)
        new_ext = self._get_ext(ev.new_path)

        if old_ext == new_ext:
            return False

        # Case 1: 블랙리스트 → 즉시 탐지
        if new_ext in SUSPICIOUS_EXTENSIONS:
            return True

        # Case 2: 정상 → 알 수 없는 확장자 (횟수 기반)
        if old_ext in NORMAL_EXTENSIONS and new_ext not in NORMAL_EXTENSIONS:
            now = time.time()
            pid = ev.pid

            if pid not in self.history:
                self.history[pid] = []

            self.history[pid].append(now)

            # 10초 window 유지
            self.history[pid] = [
                t for t in self.history[pid]
                if now - t <= self.window_sec
            ]

            if len(self.history[pid]) >= self.threshold:
                return True

        return False

    @staticmethod
    def _get_ext(path: str) -> str:
        _, ext = os.path.splitext(path)
        return ext.lower()