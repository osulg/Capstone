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

        # 탐지용 원본 데이터는 JSON 로그에 기록하지 않음
        # (sample_data: write 샘플, original_data: Entropy Delta용 write 이전 원본 샘플)
        # bytes는 JSON 직렬화가 불가능해 남겨두면 stats_collector가 TypeError로 종료된다.
        record.pop("sample_data", None)
        record.pop("original_data", None)
        self._f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def close(self) -> None:
        self._f.close()
