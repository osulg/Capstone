"""Huntress 일반 읽기 작업 검사."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scenarios.huntress_config import READ_FILES
from scenarios.huntress_tasks import execute_task


class HuntressTaskTests(unittest.TestCase):
    def execute(self, workdir, action):
        args = SimpleNamespace(
            workdir=workdir,
            action=action,
            timeout=30.0,
        )

        with patch("scenarios.huntress_tasks.time.sleep"):
            return execute_task(args)

    def test_prepare_verify_read_preserves_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            prepared = self.execute(root, "prepare")
            verified = self.execute(root, "verify")

            before = {name: (root / name).read_bytes() for name in READ_FILES}

            result = self.execute(root, "read")

            self.assertEqual(prepared["status"], "passed")
            self.assertEqual(verified["status"], "passed")
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["completed"], 6)

            for name in READ_FILES:
                self.assertEqual(
                    (root / name).read_bytes(),
                    before[name],
                )

    def test_prepare_does_not_overwrite_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / READ_FILES[0]
            path.parent.mkdir(parents=True)
            path.write_bytes(b"existing")

            result = self.execute(root, "prepare")

            self.assertEqual(result["status"], "failed")
            self.assertEqual(path.read_bytes(), b"existing")

    def test_read_failure_still_records_other_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.execute(root, "prepare")
            (root / READ_FILES[0]).unlink()

            result = self.execute(root, "read")

            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["attempted"], 6)
            self.assertEqual(result["completed"], 5)
            self.assertEqual(len(result["operations"]), 6)


if __name__ == "__main__":
    unittest.main()
