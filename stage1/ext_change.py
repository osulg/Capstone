"""
ExtChangeDetector
- rename 이벤트에서 old_path → new_path 확장자를 비교
- 랜섬웨어/악성코드가 사용하는 확장자 블랙리스트에 해당하면 탐지
- 또는 정상 확장자(문서, 이미지 등)가 알 수 없는 확장자로 바뀌는 경우도 탐지
"""

import os

# 랜섬웨어 및 악성코드에서 자주 관찰되는 확장자 블랙리스트
SUSPICIOUS_EXTENSIONS = {
    # 랜섬웨어 계열
    ".locked", ".enc", ".encrypted", ".crypt", ".crypted",
    ".cryp1", ".cerber", ".zepto", ".locky", ".wnry",
    ".wncry", ".wncryt", ".petya", ".loki", ".sage",
    # 악성코드 은닉/위장 계열
    ".evil", ".malware", ".payload",
}

# 정상적으로 사용되는 확장자 (이게 다른 확장자로 바뀌면 의심)
NORMAL_EXTENSIONS = {
    ".txt", ".doc", ".docx", ".pdf", ".xls", ".xlsx",
    ".ppt", ".pptx", ".jpg", ".jpeg", ".png", ".gif",
    ".mp4", ".mp3", ".zip", ".tar", ".gz", ".py",
    ".js", ".html", ".css", ".json", ".xml", ".csv",
}


class ExtChangeDetector:
    def check(self, ev) -> bool:
        # rename 이벤트이고 new_path가 있는 경우만 처리
        if ev.op != "rename" or not ev.new_path:
            return False

        old_ext = self._get_ext(ev.path)
        new_ext = self._get_ext(ev.new_path)

        # 확장자가 바뀌지 않으면 무시
        if old_ext == new_ext:
            return False

        # Case 1: 새 확장자가 블랙리스트에 있으면 즉시 탐지
        if new_ext in SUSPICIOUS_EXTENSIONS:
            return True

        # Case 2: 정상 확장자 → 알 수 없는 확장자로 변경
        if old_ext in NORMAL_EXTENSIONS and new_ext not in NORMAL_EXTENSIONS:
            return True

        return False

    @staticmethod
    def _get_ext(path: str) -> str:
        _, ext = os.path.splitext(path)
        return ext.lower()
