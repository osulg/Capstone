"""임시 로그로 실행별 이벤트 수집을 검사한다."""

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


class HoldFSEventTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

        self.path = Path(self.directory.name) / "events.log"
        self.path.write_bytes(b"")

        self.scope = EventScope(
            pids=frozenset({123}),
            roots=("/runtime/underlay/s01_test",),
            started_at_ns=100,
            observed_until_ns=200,
        )

    def append(self, text):
        with self.path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(text)

    def event(self, **changes):
        record = {
            "pid": 123,
            "ts_ns": 150,
            "op": "write",
            "path": "/runtime/underlay/s01_test/test.txt",
            "applied": False,
        }
        record.update(changes)
        return json.dumps(record) + "\n"

    def test_only_new_matching_events_are_collected(self):
        self.append(self.event())
        checkpoint = capture_log(self.path, "filesystem")

        self.append(self.event())
        self.append(self.event(pid=999))
        self.append(self.event(ts_ns=50))

        # 이름의 앞부분이 같은 다른 디렉터리는 대상에서 제외한다.
        self.append(self.event(path="/runtime/underlay/s01_test_other/test.txt"))

        result = collect_events(checkpoint, self.scope)

        self.assertEqual(len(result.events), 1)
        self.assertFalse(result.events[0]["applied"])
        self.assertEqual(result.issues, [])

    def test_rename_destination_is_also_matched(self):
        checkpoint = capture_log(self.path, "filesystem")

        self.append(
            self.event(
                op="rename",
                path="/runtime/underlay/other/test.txt",
                new_path="/runtime/underlay/s01_test/test.txt",
            )
        )

        result = collect_events(checkpoint, self.scope)
        self.assertEqual(len(result.events), 1)

    def test_malformed_record_is_reported(self):
        checkpoint = capture_log(self.path, "filesystem")
        self.append("not-json\n")

        result = collect_events(checkpoint, self.scope)

        self.assertEqual(result.events, [])
        self.assertTrue(result.issues)

    def test_incomplete_line_can_be_read_again(self):
        checkpoint = capture_log(self.path, "filesystem")
        line = self.event()

        self.append(line[:-1])

        first = collect_events(checkpoint, self.scope)
        self.assertTrue(first.pending_record)
        self.assertEqual(first.events, [])

        self.append("\n")

        second = collect_events(checkpoint, self.scope)
        self.assertFalse(second.pending_record)
        self.assertEqual(len(second.events), 1)

    def test_policy_path_and_pid_only_events_are_separated(self):
        checkpoint = capture_log(self.path, "policy")

        self.append(
            "[MEDIUM]\n"
            "Time: 2026-11-04 12:00:00\n"
            "PID: 123\n"
            "Target: /runtime/underlay/s01_test/test.txt\n"
            "Action: COMMIT\n"
            "Result: FILE_APPLIED\n"
            "Reason: test\n\n"
            "[MEDIUM]\n"
            "Time: 2026-11-04 12:00:00\n"
            "PID: 123\n"
            "Target: \n"
            "Action: COMMIT\n"
            "Result: DATA_APPLIED\n"
            "Reason: test\n\n"
        )

        result = collect_events(checkpoint, self.scope)

        self.assertEqual(len(result.events), 1)
        self.assertEqual(len(result.pid_only_events), 1)
        self.assertEqual(
            result.pid_only_events[0]["result"],
            "DATA_APPLIED",
        )
        self.assertEqual(result.issues, [])

    def test_incomplete_policy_block_is_pending(self):
        checkpoint = capture_log(self.path, "policy")

        self.append("[MEDIUM]\nTime: 2026-11-04 12:00:00\nPID: 123\n")

        result = collect_events(checkpoint, self.scope)

        self.assertTrue(result.pending_record)
        self.assertEqual(result.events, [])

    def test_truncated_log_is_reported(self):
        self.append("previous log contents\n")
        checkpoint = capture_log(self.path, "filesystem")

        self.path.write_bytes(b"")

        result = collect_events(checkpoint, self.scope)
        self.assertTrue(result.issues)

    def test_missing_log_is_reported(self):
        checkpoint = capture_log(self.path, "filesystem")
        self.path.unlink()

        result = collect_events(checkpoint, self.scope)
        self.assertTrue(result.issues)

    def test_read_limit_is_reported(self):
        checkpoint = capture_log(self.path, "filesystem")
        self.append(self.event())

        result = collect_events(
            checkpoint,
            self.scope,
            max_bytes=10,
        )

        self.assertTrue(result.issues)


if __name__ == "__main__":
    unittest.main()
