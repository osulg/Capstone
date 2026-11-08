"""허니팟의 접근 PID와 정확한 경로 범위 검사."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(BACKEND))

from app.services.holdfs_events import (
    EventScope,
    capture_log,
    collect_events,
)


class HoneypotEventScopeTests(unittest.TestCase):
    def test_exact_paths_exclude_other_files_and_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_bytes(b"")
            checkpoint = capture_log(path, "filesystem")

            root = "/runtime/underlay/honeypot"
            records = [
                # 디렉터리 접근과 지정 미끼 접근은 수집한다.
                {"pid": 123, "path": root},
                {"pid": 123, "path": root + "/id_rsa"},
                # 다른 미끼·하위 경로·유사 이름은 수집하지 않는다.
                {"pid": 123, "path": root + "/other.txt"},
                {"pid": 123, "path": root + "/id_rsa/child"},
                {"pid": 123, "path": root + "_other/id_rsa"},
                # 같은 경로라도 다른 PID의 이벤트는 제외한다.
                {"pid": 999, "path": root + "/id_rsa"},
            ]

            with path.open(
                "a",
                encoding="utf-8",
                newline="\n",
            ) as stream:
                for record in records:
                    stream.write(
                        json.dumps(
                            {
                                **record,
                                "ts_ns": 150,
                                "op": "lookup",
                                "applied": False,
                            }
                        )
                        + "\n"
                    )

            scope = EventScope(
                pids=frozenset({123}),
                roots=(),
                exact_paths=(
                    root,
                    root + "/id_rsa",
                ),
                started_at_ns=100,
                observed_until_ns=200,
            )

            result = collect_events(checkpoint, scope)

            self.assertEqual(
                [event["path"] for event in result.events],
                [root, root + "/id_rsa"],
            )
            self.assertEqual(result.issues, [])

    def test_scope_without_paths_is_rejected(self):
        with self.assertRaises(ValueError):
            EventScope(
                pids=frozenset({123}),
                roots=(),
                started_at_ns=100,
                observed_until_ns=200,
            )


if __name__ == "__main__":
    unittest.main()
