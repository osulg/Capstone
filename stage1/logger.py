"""
EventLogger
- FsEvent를 JSONL 파일에 기록하는 역할만 담당
- stats_collector에서 분리
"""

import json
from dataclasses import asdict


class EventLogger:
    def __init__(self, log_path: str):
        self._f = open(log_path, "a", buffering=1)

    def write(self, ev) -> None:
        self._f.write(json.dumps(asdict(ev), ensure_ascii=False) + "\n")

    def close(self) -> None:
        self._f.close()
