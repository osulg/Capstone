"""허니팟 관리자의 분기·대상 경로·관찰 결과 검사."""

import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from scenarios import s02_huntress as manager
from scenarios.huntress_config import HONEYPOT_FILES
from scenarios.results import validate_result_details


class HoneypotManagerTests(unittest.TestCase):
    def run_case(self, *, fail_check=False, timeout=False, reject=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mount, underlay = root / "mount", root / "underlay"
            mount.mkdir()
            underlay.mkdir()
            args = SimpleNamespace(
                mode="honeypot", mount=mount, underlay=underlay,
                worker_python=Path(sys.executable), work_dir_name="s02_" + "a" * 32,
                holdfs_pid=999, prepare_timeout=1.0, total_timeout=120.0,
            )
            roles = []

            @contextmanager
            def worker(scenario_id, role, command, **kwargs):
                # 실제 시작 승인 로직은 workers의 별도 검사에서 검증한다.
                roles.append(role)
                self.assertIn("scenarios.huntress_honeypot_tasks", command)
                self.assertNotIn("--workdir", command)
                action = command[command.index("scenarios.huntress_honeypot_tasks") + 1]
                if action == "access" and reject:
                    raise RuntimeError("접근 PID 등록 거절")
                target = (underlay if action == "check" else mount) / "honeypot"
                failed = action == "check" and fail_check
                operations = [] if failed else [
                    {"name": name, "path": str(target / name),
                     "outcome": "ready" if action == "check" else "permission_denied"}
                    for name in HONEYPOT_FILES
                ]
                payload = {
                    "action": action, "status": "failed" if failed else "passed",
                    "planned": 5, "attempted": 1 if failed else 5,
                    "completed": 0 if failed else 5,
                    "operations": operations,
                    "failure": {"operation": action, "path": str(target), "errno": 2,
                                "message": "미끼 누락"} if failed else None,
                }
                process = Mock(stdin=None, returncode=1 if failed else 0)
                if action == "access" and timeout:
                    process.communicate.side_effect = subprocess.TimeoutExpired(command, 1)
                else:
                    process.communicate.return_value = (json.dumps(payload).encode(), None)
                try:
                    yield process, {"role": role, "pid": 200 + len(roles), "start_time_ticks": 1}
                finally:
                    process.wait()

            with (
                patch.object(manager.sys, "platform", "linux"),
                patch.object(manager, "check_health"),
                patch.object(manager, "emit_progress"),
                patch.object(manager, "register_process_and_wait", return_value={
                    "role": "huntress_manager", "pid": 100, "start_time_ticks": 1,
                }),
                patch.object(manager, "registered_worker", side_effect=worker),
            ):
                report = manager.run(args)
            self.assertFalse((mount / args.work_dir_name).exists())
            self.assertEqual(report["mode"], "honeypot")
            self.assertIsNotNone(report["finished_at"])
            validate_result_details(report)
            return report, roles

    def test_check_precedes_access_and_preserves_observation_scope(self):
        report, roles = self.run_case()
        self.assertEqual(roles, ["huntress_honeypot_check", "huntress_honeypot_access"])
        self.assertEqual(report["status"], "passed")
        self.assertTrue(report["honeypot_observation"]["access_started"])
        self.assertEqual(report["honeypot_observation"]["policy_verification"], "not_checked")
        self.assertEqual([step["name"] for step in report["steps"]],
                         ["PRECHECK", "HONEYPOT_READY", "HONEYPOT_ACCESS"])

    def test_missing_decoys_prevent_access(self):
        report, roles = self.run_case(fail_check=True)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(roles, ["huntress_honeypot_check"])
        self.assertFalse(report["honeypot_observation"]["access_started"])

    def test_timeout_preserves_access_start_information(self):
        report, _ = self.run_case(timeout=True)
        self.assertEqual(report["status"], "timed_out")
        self.assertTrue(report["honeypot_observation"]["access_started"])

    def test_registration_rejection_does_not_mark_access_started(self):
        report, _ = self.run_case(reject=True)
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["honeypot_observation"]["access_started"])


if __name__ == "__main__":
    unittest.main()
