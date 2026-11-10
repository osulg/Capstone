"""허니팟 미끼 사전 확인과 접근 결과 구분 검사."""

import errno
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scenarios.huntress_honeypot import (
    DECOY_NAMES,
    execute_task,
)


class HoneypotTaskTests(unittest.TestCase):
    def make_args(self, root, action):
        return SimpleNamespace(
            action=action,
            mount=root / "mount",
            underlay=root / "underlay",
            timeout=30.0,
        )

    def prepare_decoys(self, root):
        directory = root / "honeypot"
        directory.mkdir(parents=True)

        for name in DECOY_NAMES:
            (directory / name).write_bytes(b"DUMMY DECOY\n")

        return directory

    def test_precheck_uses_underlay_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.make_args(root, "check")

            # mount에는 미끼를 만들지 않는다.
            self.prepare_decoys(args.underlay)

            result = execute_task(args)

            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["completed"], 5)
            self.assertFalse(args.mount.exists())

    def test_missing_decoy_fails_precheck(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.make_args(root, "check")
            decoys = self.prepare_decoys(args.underlay)
            (decoys / DECOY_NAMES[0]).unlink()

            result = execute_task(args)

            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["completed"], 0)
            self.assertEqual(
                result["failure"]["errno"],
                errno.ENOENT,
            )

    def test_access_uses_mount_and_preserves_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.make_args(root, "access")
            decoys = self.prepare_decoys(args.mount)

            with patch("scenarios.huntress_honeypot.time.sleep"):
                result = execute_task(args)

            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["completed"], 5)

            for operation in result["operations"]:
                self.assertEqual(operation["access"], "read")

            for name in DECOY_NAMES:
                self.assertEqual(
                    (decoys / name).read_bytes(),
                    b"DUMMY DECOY\n",
                )

    def test_permission_denied_is_recorded_as_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.make_args(Path(directory), "access")

            with (
                patch.object(
                    Path,
                    "open",
                    side_effect=PermissionError(
                        errno.EACCES,
                        "테스트용 접근 거절",
                    ),
                ),
                patch("scenarios.huntress_honeypot.time.sleep"),
            ):
                result = execute_task(args)

            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["completed"], 5)
            self.assertTrue(
                all(item["access"] == "denied" for item in result["operations"])
            )

    def test_missing_files_are_distinguished_from_permission_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.make_args(Path(directory), "access")

            with patch("scenarios.huntress_honeypot.time.sleep"):
                result = execute_task(args)

            self.assertTrue(
                all(item["access"] == "missing" for item in result["operations"])
            )


if __name__ == "__main__":
    unittest.main()
