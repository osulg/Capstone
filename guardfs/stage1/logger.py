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
        record = asdict(ev)

        # 탐지용 바이트 표본은 제외하고 계산된 엔트로피 수치만 기록
        record.pop("sample_data", None)
        record.pop("original_data", None)

        self._f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def close(self) -> None:
        self._f.close()
