"""Registration response protocol checks without a real FUSE mount."""

import json
import os
import sys
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import Mock, patch

from scenarios.common import register_process_and_wait


class RegistrationAckTests(unittest.TestCase):
    def receive(self, changes=None, *, eof=False, timeout=False):
        reply = {
            "type": "process_registered", "request_id": "request-1",
            "scenario_id": "S01", "status": "accepted",
            "role": "normal_worker", "pid": 123,
            "start_time_ticks": 456, "error": None,
        }
        reply.update(changes or {})
        data = b"" if eof else (json.dumps(reply) + "\n").encode()

        with ExitStack() as stack:
            stack.enter_context(patch("scenarios.common.sys.platform", "linux"))
            stack.enter_context(patch("scenarios.common.sys.stdin", Mock()))
            stack.enter_context(patch("scenarios.common.os.getpid", return_value=123))
            stack.enter_context(patch(
                "scenarios.common.get_process_start_time", return_value=456
            ))
            stack.enter_context(patch(
                "scenarios.common.uuid.uuid4",
                return_value=SimpleNamespace(hex="request-1"),
            ))
            selector = stack.enter_context(patch(
                "scenarios.common.selectors.PollSelector", create=True
            )).return_value.__enter__.return_value
            selector.select.return_value = [] if timeout else [object()]
            stack.enter_context(patch("scenarios.common.os.read", return_value=data))
            emit = stack.enter_context(patch("scenarios.common._emit_event"))
            result = register_process_and_wait("S01", "normal_worker")
            self.assertEqual(emit.call_args.args[0]["request_id"], "request-1")
            return result

    def test_accepts_matching_response(self):
        self.assertEqual(self.receive()["pid"], 123)

    def test_rejects_wrong_request_id(self):
        with self.assertRaisesRegex(RuntimeError, "현재 요청"):
            self.receive({"request_id": "another-request"})

    def test_rejection_is_reported(self):
        with self.assertRaisesRegex(RuntimeError, "등록 거절"):
            self.receive({"status": "rejected", "error": "invalid identity"})

    def test_eof_is_reported(self):
        with self.assertRaisesRegex(RuntimeError, "통로가 종료"):
            self.receive(eof=True)

    def test_timeout_is_reported(self):
        with self.assertRaisesRegex(RuntimeError, "시간이 초과"):
            self.receive(timeout=True)

    @unittest.skipUnless(sys.platform == "linux", "Real poll fd test needs Linux")
    def test_real_devnull_reports_eof(self):
        # 실제 Linux fd로 epoll EPERM 회귀를 검사한다. FUSE는 필요 없다.
        with open(os.devnull, "rb") as reader, patch(
            "scenarios.common.sys.stdin", reader
        ), patch("scenarios.common._emit_event"):
            with self.assertRaisesRegex(RuntimeError, "통로가 종료"):
                register_process_and_wait("S01", "normal_worker")


if __name__ == "__main__":
    unittest.main()
