"""
ExtChangeDetector

탐지 정책:
- 알려진 악성 확장자로 변경되면 즉시 탐지
- 문서·이미지 확장자 뒤에 실행 확장자가 추가되면 즉시 탐지 (이중 확장자)
- 정상 확장자에서 알 수 없는 확장자로 여러 파일이 변경되면 PID별 시간 창을 기준으로 탐지
- 동일 파일의 반복 rename은 임계 횟수에 중복 반영하지 않음
"""

import os
import time
from pathlib import PurePath
from typing import Dict, List, Tuple

from guardfs.common.config import (
    EXT_CHANGE_THRESHOLD,
    EXT_CHANGE_WINDOW_SEC,
)

# 랜섬웨어 및 악성코드에서 자주 관찰되는 확장자
SUSPICIOUS_EXTENSIONS = {
    ".locked",
    ".enc",
    ".encrypted",
    ".crypt",
    ".crypted",
    ".cryp1",
    ".cerber",
    ".zepto",
    ".locky",
    ".wnry",
    ".wncry",
    ".wncryt",
    ".petya",
    ".loki",
    ".sage",
    ".evil",
    ".malware",
    ".payload",
}

# 정상 확장자
NORMAL_EXTENSIONS = {
    ".txt",
    ".doc",
    ".docx",
    ".pdf",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".mp4",
    ".mp3",
    ".zip",
    ".tar",
    ".gz",
    ".py",
    ".js",
    ".html",
    ".css",
    ".json",
    ".xml",
    ".csv",
}

# 문서·이미지 파일 뒤에 붙으면 위상 가능성이 있는 실행 확장자
EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".scr",
    ".com",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jar",
    ".msi",
}

# timestamp, normalized old path, new extension
HistoryEntry = Tuple[float, str, str]


class ExtChangeDetector:
    def __init__(
        self,
        window_sec: float = EXT_CHANGE_WINDOW_SEC,
        threshold: int = EXT_CHANGE_THRESHOLD,
    ):
        self._validate_config(window_sec, threshold)

        self.window_sec = window_sec
        self.threshold = threshold

        # pid -> extension change records
        self.history: Dict[int, List[HistoryEntry]] = {}

    @staticmethod
    def _validate_config(
        window_sec: float,
        threshold: int,
    ) -> None:
        """잘못된 탐지 설정을 초기화 단계에서 거부"""

        if window_sec <= 0:
            raise ValueError("window_sec must be greater than zero")

        if threshold <= 0:
            raise ValueError("threshold must be greater than zero")

    @staticmethod
    def _get_ext(path: str) -> str:
        """경로의 마지막 확장자를 소문자로 변환"""

        _, extension = os.path.splitext(path)
        return extension.lower()

    @staticmethod
    def _get_suffixes(path: str) -> List[str]:
        """파일명에 포함된 모든 확장자를 소문자로 변환"""

        return [suffix.lower() for suffix in PurePath(path).suffixes]

    @classmethod
    def _has_suspicious_double_extension(
        cls,
        path: str,
    ) -> bool:
        """문서·이미지 확장자 뒤에 실행 확장자가 붙었는지 확인"""
        suffixes = cls._get_suffixes(path)

        if len(suffixes) < 2:
            return False

        visible_extension = suffixes[-2]
        final_extension = suffixes[-1]

        return (
            visible_extension in NORMAL_EXTENSIONS
            and final_extension in EXECUTABLE_EXTENSIONS
        )

    @classmethod
    def _is_new_suspicious_double_extension(
        cls,
        old_path: str,
        new_path: str,
    ) -> bool:
        """rename으로 의심스러운 이중 확장자가 새로 생겼는지 확인"""

        old_is_suspicious = cls._has_suspicious_double_extension(old_path)
        new_is_suspicious = cls._has_suspicious_double_extension(new_path)

        return new_is_suspicious and not old_is_suspicious

    @staticmethod
    def _is_suspicious_extension(
        extension: str,
    ) -> bool:
        """알려진 악성 확장자인지 확인"""

        return extension in SUSPICIOUS_EXTENSIONS

    @staticmethod
    def _should_accumulate(
        old_extension: str,
        new_extension: str,
    ) -> bool:
        """시간 창 누적 대상으로 bool 확장자 변경인지 확인"""

        if old_extension not in NORMAL_EXTENSIONS:
            return False

        if new_extension in NORMAL_EXTENSIONS:
            return False

        # new_extension == ""인 확장자 제거도 포함
        return True

    def _cleanup_expired(self, now: float) -> None:
        """모든 PID에서 시간 창을 벗어난 기록을 제거"""

        for pid, entries in list(self.history.items()):
            active_entries = [
                entry for entry in entries if now - entry[0] <= self.window_sec
            ]

            if active_entries:
                self.history[pid] = active_entries
            else:
                self.history.pop(pid, None)

    def _record_change(
        self,
        pid: int,
        old_path: str,
        new_extension: str,
        now: float,
    ) -> bool:
        """변경을 기록하고 서로 다른 파일 수가 임계값에 도달했는지 확인"""

        # window_sec을 지난 과거 이벤트 제거
        self._cleanup_expired(now)

        normalized_path = os.path.realpath(old_path)
        pid_history = self.history.setdefault(pid, [])

        pid_history.append(
            (
                now,
                normalized_path,
                new_extension,
            )
        )

        distinct_paths = {path for _, path, _ in pid_history}

        if len(distinct_paths) >= self.threshold:
            self.history.pop(pid, None)
            return True

        return False

    def check_immediate(self, ev) -> bool:
        """한 번의 rename으로 판단 가능한 강한 위험 신호 검사"""

        if ev.op != "rename" or not ev.new_path:
            return False

        old_extension = self._get_ext(ev.path)
        new_extension = self._get_ext(ev.new_path)

        # 새롭게 생성된 위험한 이중 확장자
        if self._is_new_suspicious_double_extension(
            ev.path,
            ev.new_path,
        ):
            return True

        # 마지막 확장자가 동일한 일반 rename
        if old_extension == new_extension:
            return False

        # 알려진 랜섬웨어 확장자
        return self._is_suspicious_extension(new_extension)

    def check(self, ev) -> bool:
        """확장자 변경 이벤트가 의심스러운지 판정"""

        if ev.op != "rename" or not ev.new_path:
            return False

        # 강한 신호는 즉시 탐지
        if self.check_immediate(ev):
            return True

        old_path = ev.path
        new_path = ev.new_path

        old_extension = self._get_ext(old_path)
        new_extension = self._get_ext(new_path)

        # 실제 확장자 변화가 없는 일반 rename
        if old_extension == new_extension:
            return False

        # 정상 -> unknown 변경이 아니면 누적하지 않음
        if not self._should_accumulate(
            old_extension,
            new_extension,
        ):
            return False

        now = time.monotonic()

        return self._record_change(
            pid=ev.pid,
            old_path=old_path,
            new_extension=new_extension,
            now=now,
        )
