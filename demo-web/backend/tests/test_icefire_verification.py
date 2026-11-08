"""원본 보존·차단 근거·종료 확인 조합의 판정 검사."""

import json
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(BACKEND.parents[1]))

from app.services.icefire_verification import verify_protection


class ProtectionTests(unittest.TestCase):
    def record(self):
        root = "/runtime/underlay/s01_" + "a" * 32
        return NS(
            run_id="a" * 32, status="timed_out",
            result={"execution_scope": "full", "attack_started": True},
            workspace=NS(name="s01_" + "a" * 32,
                         mount_path="/runtime/mount/s01_" + "a" * 32, underlay_path=root),
            processes=[NS(role="icefire_attack", pid=123, start_time_ticks=5)],
            event_collection=NS(issues=[], pending_record=False, events=[{
                "source": "policy", "pid": 123, "level": "HIGH",
                "op": "WRITE", "result": "BLOCKED", "path": root + "/doc_000.docx",
            }]),
        )

    def files(self):
        return [{"name": f"doc_{i:03d}{('.docx', '.pdf', '.xlsx')[i % 3]}",
                 "mount": "matched", "underlay": "matched"} for i in range(10)]

    def check(self, record=None, files=None, cleanup=True):
        with patch("app.services.icefire_verification.subprocess.run", return_value=NS(
            stdout=json.dumps(self.files() if files is None else files).encode(),
        )) as process:
            result = verify_protection(record or self.record(), cleanup_confirmed=cleanup)
            return result, process.call_count

    def test_blocked_and_preserved_passes(self):
        result, calls = self.check()
        self.assertEqual(result["status"], "passed")
        self.assertEqual(calls, 1)

    def test_changed_or_missing_file_fails(self):
        for state in ("changed", "missing"):
            with self.subTest(state=state):
                files = self.files()
                files[0]["mount"] = state
                result, _ = self.check(files=files)
                self.assertEqual(result["status"], "failed")

    def test_wrong_pid_or_path_does_not_prove_blocking(self):
        for key, value in (("pid", 999), ("path", "/other/file")):
            with self.subTest(key=key):
                record = self.record()
                record.event_collection.events[0][key] = value
                result, _ = self.check(record)
                self.assertEqual(result["status"], "unknown")

    def test_incomplete_logs_or_unreadable_file_are_unknown(self):
        record = self.record()
        record.event_collection.issues = ["로그 누락"]
        self.assertEqual(self.check(record)[0]["status"], "unknown")
        files = self.files()
        files[0]["mount"] = "unknown"
        self.assertEqual(self.check(files=files)[0]["status"], "unknown")

    def test_unconfirmed_cleanup_or_cancellation_skips_reader(self):
        self.assertEqual(self.check(cleanup=False)[1], 0)
        record = self.record()
        record.status = "cancelled"
        self.assertEqual(self.check(record)[1], 0)

    def test_verifier_timeout_is_unknown(self):
        with patch("app.services.icefire_verification.subprocess.run",
                   side_effect=subprocess.TimeoutExpired("verify", 15)):
            result = verify_protection(self.record(), cleanup_confirmed=True)
        self.assertEqual(result["status"], "unknown")

    def test_incomplete_file_list_cannot_pass(self):
        self.assertEqual(self.check(files=self.files()[:-1])[0]["status"], "unknown")


if __name__ == "__main__":
    unittest.main()
