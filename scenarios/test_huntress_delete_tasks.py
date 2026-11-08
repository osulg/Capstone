"""로그 삭제 작업의 실제 파일 상태와 부분 차단 검사."""

import errno
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scenarios.huntress_config import DELETE_FILES
from scenarios.huntress_delete_tasks import execute_task


class HuntressDeleteTaskTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def prepare(self):
        result = execute_task("prepare", self.root, 5)
        self.assertEqual(result["status"], "passed")
        return result

    def test_prepare_verify_delete_and_inspect(self):
        self.prepare()

        verified = execute_task("verify", self.root, 5)
        self.assertEqual(verified["status"], "passed")
        self.assertEqual(verified["completed"], 12)

        deleted = execute_task("delete", self.root, 5)
        self.assertEqual(deleted["status"], "passed")
        self.assertTrue(
            all(item["outcome"] == "unlink_succeeded" for item in deleted["operations"])
        )

        inspected = execute_task("inspect", self.root, 5)
        self.assertTrue(
            all(item["state"] == "missing" for item in inspected["operations"])
        )

    def test_prepare_does_not_overwrite_existing_file(self):
        target = self.root / DELETE_FILES[0]
        target.write_bytes(b"existing")

        result = execute_task("prepare", self.root, 5)

        self.assertEqual(result["status"], "failed")
        self.assertEqual(target.read_bytes(), b"existing")

    def test_partial_block_does_not_hide_deleted_files(self):
        self.prepare()
        original_unlink = Path.unlink
        blocked = DELETE_FILES[-1]

        def controlled_unlink(path, *args, **kwargs):
            if path.name == blocked:
                raise PermissionError(errno.EACCES, "test block", str(path))
            return original_unlink(path, *args, **kwargs)

        with patch.object(Path, "unlink", new=controlled_unlink):
            result = execute_task("delete", self.root, 5)

        self.assertEqual(result["completed"], 12)
        self.assertEqual(
            result["operations"][-1]["outcome"],
            "permission_denied",
        )

        inspected = execute_task("inspect", self.root, 5)
        states = [item["state"] for item in inspected["operations"]]

        self.assertEqual(states.count("missing"), 11)
        self.assertEqual(states.count("matched"), 1)

    def test_inspect_distinguishes_changed_and_missing_files(self):
        self.prepare()
        (self.root / DELETE_FILES[0]).write_bytes(b"changed")
        (self.root / DELETE_FILES[1]).unlink()

        result = execute_task("inspect", self.root, 5)

        self.assertEqual(result["operations"][0]["state"], "changed")
        self.assertEqual(result["operations"][1]["state"], "missing")
        self.assertEqual(result["operations"][2]["state"], "matched")

    def test_expired_deadline_prevents_deletion(self):
        self.prepare()

        result = execute_task("delete", self.root, 0)

        self.assertEqual(result["status"], "timed_out")
        self.assertEqual(result["attempted"], 0)
        self.assertTrue(all((self.root / name).exists() for name in DELETE_FILES))


if __name__ == "__main__":
    unittest.main()
