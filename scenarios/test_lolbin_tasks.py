"""S04 작업 분리와 결과 검증을 일반 임시 폴더에서 확인한다."""

import json
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from contextlib import contextmanager
from unittest.mock import patch

from scenarios.lolbin_results import validate_lolbin_success, is_attack_permission_denied
from experiments.simulators import sim_highentropy
from scenarios import s04_lolbin

SCRIPT = Path(__file__).resolve().parents[1] / "experiments/simulators/sim_highentropy.py"


class LolbinTaskTests(unittest.TestCase):
    def test_rename_denial_preserves_errno_and_operation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / ("s04_" + "a" * 32)
            root.mkdir()
            args = SimpleNamespace(target=str(root), size_kb=1, duration=30,
                                   web_action="attack", files=20, chunk_kb=16, delay=0)
            output = io.StringIO()
            with (patch.object(sim_highentropy, "overwrite_with_random"),
                  patch.object(sim_highentropy.os, "rename", side_effect=PermissionError(13, "denied")),
                  patch.object(sys, "stdout", output)):
                self.assertEqual(sim_highentropy.run_web_task(args), 1)
            result = json.loads(output.getvalue())
            self.assertEqual(result["failure"]["errno"], 13)
            self.assertEqual(result["failure"]["operation"], "rename")
            self.assertTrue(is_attack_permission_denied(result))
            result["failure"]["errno"] = 5
            self.assertFalse(is_attack_permission_denied(result))

    def test_denied_attack_continues_to_both_inspections(self):
        calls = []
        workers = []

        @contextmanager
        def worker(scenario_id, role, command, **kwargs):
            action = command[command.index("--web-action") + 1]
            calls.append(role)
            pid = 100 + len(calls)
            metadata = {"role": role, "pid": pid, "start_time_ticks": 123}
            workers.append(SimpleNamespace(**metadata))
            payload = {"action": action, "pid": pid, "status": "passed", "error": None,
                       "files": [{"name": f"file_{i:03d}.txt", "original": "matched",
                                  "renamed": "missing"} for i in range(20)]}
            if action == "attack":
                payload.update(status="failed", error="denied", files=[],
                               failure={"errno": 13, "operation": "rename",
                                        "path": command[3] + "/file_000.txt", "message": "denied"})
            process = SimpleNamespace(pid=pid, stdin=None,
                                      returncode=1 if action == "attack" else 0,
                                      communicate=lambda **kwargs: (json.dumps(payload).encode(), None))
            yield process, metadata

        with tempfile.TemporaryDirectory() as directory:
            mount = Path(directory) / "mount"
            underlay = Path(directory) / "underlay"
            mount.mkdir()
            underlay.mkdir()
            args = SimpleNamespace(mount=mount, underlay=underlay,
                                   work_dir_name="s04_" + "a" * 32, holdfs_pid=1)
            with (patch.object(s04_lolbin.sys, "platform", "linux"),
                  patch.object(s04_lolbin, "SYSTEM_PYTHON", Path(sys.executable)),
                  patch.object(s04_lolbin, "INSTALLED_SCRIPT", SCRIPT),
                  patch.object(s04_lolbin, "check_health"),
                  patch.object(s04_lolbin, "capture_policy_position", return_value=None),
                  patch.object(s04_lolbin, "emit_progress"),
                  patch.object(s04_lolbin, "register_process_and_wait", return_value={}),
                  patch.object(s04_lolbin, "registered_worker", worker)):
                report = s04_lolbin.run(args)
            self.assertEqual(report["status"], "passed", report)
            self.assertEqual(report["worker_outcome"]["status"], "permission_denied")
            self.assertEqual(calls[-2:], ["lolbin_inspect_mount", "lolbin_inspect_underlay"])
            validate_lolbin_success(report, SimpleNamespace(processes=workers))
            report["task_results"][3]["failure"]["errno"] = 5
            with self.assertRaises(ValueError):
                validate_lolbin_success(report, SimpleNamespace(processes=workers))

    def test_task_lifecycle_without_forked_workers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / ("s04_" + "a" * 32)
            for action in ("prepare", "verify", "attack", "inspect"):
                command = [sys.executable, str(SCRIPT), str(root), "--web-action", action,
                           "--files", "2", "--size-kb", "1", "--delay", "0", "--keep"]
                result = subprocess.run(command, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                report = json.loads(result.stdout)
                self.assertEqual(report["status"], "passed")
                self.assertEqual(len(report["files"]), 2)
            self.assertTrue(all(item["original"] == "missing" for item in report["files"]))
            self.assertTrue(all(item["renamed"] == "changed" for item in report["files"]))

    def test_unregistered_attack_is_rejected(self):
        record = SimpleNamespace(processes=[])
        result = {"result_version": 2, "attack_started": True,
                  "worker_outcome": {"status": "completed", "pid": 123, "returncode": 0}}
        with self.assertRaisesRegex(ValueError, "등록되지"):
            validate_lolbin_success(result, record)

    def test_reaped_worker_with_wrong_start_tick_is_rejected(self):
        record = SimpleNamespace(processes=[SimpleNamespace(
            role="lolbin_attack", pid=123, start_time_ticks=456)])
        result = {"result_version": 2, "attack_started": True,
                  "worker_outcome": {"status": "stopped_reaped", "pid": 123,
                                     "returncode": -9, "start_time_ticks": 999}}
        with self.assertRaisesRegex(ValueError, "회수 근거"):
            validate_lolbin_success(result, record)


if __name__ == "__main__":
    unittest.main()
