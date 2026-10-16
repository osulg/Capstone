"""Report/control-flow checks; these do not replace Linux FUSE tests."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scenarios.s01_normal import run, wait_until


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
            with patch("scenarios.s01_normal.sys.platform", "linux"), patch(
                "scenarios.s01_normal.check_health",
                side_effect=RuntimeError("disconnected"),
            ):
                result = run(mount, underlay, guardfs_pid=123)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["steps"][0]["name"], "PRECHECK")
            self.assertEqual(list(mount.iterdir()), [])
            self.assertEqual(list(underlay.iterdir()), [])

    def test_local_lifecycle_report_and_cleanup(self):
        # Model the second view without claiming any actual FUSE verification.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            events = []
            (root / "view").mkdir()
            with patch("scenarios.s01_normal.sys.platform", "linux"), patch(
                "scenarios.s01_normal.check_health"
            ), patch(
                "scenarios.s01_normal.Path.resolve", return_value=root / "view" / ".."
            ):
                result = run(root, root, guardfs_pid=123, on_step=events.append)
            self.assertEqual(result["status"], "passed")
            self.assertEqual(len(events), 10)
            self.assertIsNone(result["artifact_path"])
            self.assertEqual(result["detection_verification"], "not_checked")
            self.assertEqual(list(root.iterdir()), [root / "view"])


if __name__ == "__main__":
    unittest.main()
