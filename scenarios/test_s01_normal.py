"""Report/control-flow checks; these do not replace Linux FUSE tests."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from scenarios.s01_normal import main, run, wait_until


class NormalScenarioTests(unittest.TestCase):
    def test_delayed_propagation_is_rechecked(self):
        probe = Mock(side_effect=[False, False, True])
        health = Mock()
        with patch("scenarios.s01_normal.time.sleep"):
            wait_until(probe, health, timeout=1)
        self.assertEqual(probe.call_count, 3)
        self.assertEqual(health.call_count, 3)

    def test_permission_failure_is_not_retried(self):
        probe = Mock(side_effect=PermissionError("denied"))
        with self.assertRaises(PermissionError):
            wait_until(probe, Mock(), timeout=1)
        self.assertEqual(probe.call_count, 1)

    def test_propagation_timeout(self):
        with self.assertRaisesRegex(RuntimeError, "Propagation not confirmed"):
            wait_until(lambda: False, Mock(), timeout=0.001, interval=0.001)

    def test_disconnected_mount_stops_before_creating_files(self):
        with tempfile.TemporaryDirectory() as temp:
            mount = Path(temp) / "mount"
            underlay = Path(temp) / "underlay"
            mount.mkdir()
            underlay.mkdir()
            progress = []
            with patch("scenarios.s01_normal.sys.platform", "linux"), patch(
                "scenarios.s01_normal.check_health",
                side_effect=RuntimeError("disconnected"),
            ):
                result = run(
                    mount, underlay, guardfs_pid=123, on_progress=progress.append
                )
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["steps"][0]["name"], "PRECHECK")
            self.assertEqual(list(mount.iterdir()), [])
            self.assertEqual(list(underlay.iterdir()), [])
            self.assertEqual([s["status"] for s in progress], ["running", "failed"])
            self.assertTrue(all(s["name"] == "PRECHECK" for s in progress))

    def test_local_lifecycle_report_and_cleanup(self):
        # Model the second view without claiming any actual FUSE verification.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            events = []
            progress = []
            (root / "view").mkdir()
            with patch("scenarios.s01_normal.sys.platform", "linux"), patch(
                "scenarios.s01_normal.check_health"
            ), patch(
                "scenarios.s01_normal.Path.resolve", return_value=root / "view" / ".."
            ):
                result = run(
                    root, root, guardfs_pid=123, on_step=events.append,
                    on_progress=progress.append,
                )
            self.assertEqual(result["status"], "passed")
            self.assertEqual(len(events), 10)
            self.assertIsNone(result["artifact_path"])
            self.assertEqual(result["detection_verification"], "not_checked")
            self.assertEqual(list(root.iterdir()), [root / "view"])
            self.assertEqual(len(progress), 20)
            for index, completed in enumerate(result["steps"]):
                started, finished = progress[index * 2:index * 2 + 2]
                self.assertEqual(started["name"], completed["name"])
                self.assertEqual(started["status"], "running")
                self.assertNotIn("finished_at", started)
                self.assertEqual(finished, completed)

    def test_cli_separates_progress_from_final_json(self):
        def simulated_run(**kwargs):
            kwargs["on_progress"]({"name": "PRECHECK", "status": "running"})
            kwargs["on_progress"]({"name": "PRECHECK", "status": "failed"})
            return {"scenario_id": "S01", "status": "failed"}

        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("scenarios.s01_normal.sys.argv", ["s01_normal"]), patch(
            "scenarios.s01_normal.run", side_effect=simulated_run
        ), redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = main()

        self.assertEqual(exit_code, 1)
        self.assertEqual(json.loads(stdout.getvalue())["status"], "failed")
        lines = stderr.getvalue().splitlines()
        self.assertEqual(len(lines), 2)
        for line in lines:
            self.assertTrue(line.startswith("PROGRESS "))
            event = json.loads(line.removeprefix("PROGRESS "))
            self.assertEqual(event["type"], "step")
            self.assertEqual(event["scenario_id"], "S01")


if __name__ == "__main__":
    unittest.main()
