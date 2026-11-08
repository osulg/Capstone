"""파일 연산을 가짜 함수로 대체한 IceFire 공격 집계 검사."""

import errno
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

from scenarios import icefire_tasks as tasks
from scenarios.icefire_config import FILE_COUNT, expected_operations


class IceFireAttackTests(unittest.TestCase):
    def run_attack(self, *, fail_write=False, expired=False):
        args = SimpleNamespace(workdir="/simulation/workdir", files=FILE_COUNT, size_kb=64, timeout=30)
        with ExitStack() as stack:
            stack.enter_context(patch.object(tasks.time, "sleep"))
            stack.enter_context(patch.object(
                tasks.time, "monotonic",
                side_effect=[0, 31] if expired else None, return_value=0,
            ))
            mocks = [stack.enter_context(patch.object(tasks.lib, name)) for name in (
                "read_file", "overwrite_random", "rename_to", "write_note",
            )]
            mocks.append(stack.enter_context(patch.object(tasks.os, "unlink")))
            if fail_write:
                mocks[1].side_effect = PermissionError(errno.EACCES, "쓰기 거절")
            result = tasks.execute_attack(args)
            return result, [mock.call_count for mock in mocks]

    def test_all_32_operations_complete(self):
        result, counts = self.run_attack()
        self.assertEqual(result["status"], "passed")
        self.assertEqual(counts, [10, 10, 10, 1, 1])
        self.assertEqual(result["planned"], expected_operations("attack"))
        self.assertEqual(result["attempted"], 32)
        self.assertEqual(result["completed"], 32)

    def test_write_failure_preserves_partial_count_and_errno(self):
        result, counts = self.run_attack(fail_write=True)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(counts, [1, 1, 0, 0, 0])
        self.assertEqual(result["attempted"], 2)
        self.assertEqual(result["completed"], 1)
        self.assertEqual(result["failure"]["errno"], errno.EACCES)
        self.assertTrue(result["operations"][-1]["attempted"])

    def test_expired_deadline_prevents_file_operation(self):
        result, counts = self.run_attack(expired=True)
        self.assertEqual(result["status"], "timed_out")
        self.assertEqual(counts, [0, 0, 0, 0, 0])
        self.assertEqual(result["attempted"], 0)
        self.assertEqual(result["completed"], 0)
        self.assertFalse(result["operations"][-1]["attempted"])


if __name__ == "__main__":
    unittest.main()
