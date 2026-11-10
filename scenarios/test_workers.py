"""자식의 등록 전 대기와 등록 실패 시 회수를 검사한다."""

import subprocess
import sys
import unittest
from unittest.mock import patch

from scenarios.workers import registered_worker


@unittest.skipUnless(
    sys.platform == "linux",
    "자식 실행 제어 검사는 Linux에서 수행합니다.",
)
class RegisteredWorkerTests(unittest.TestCase):
    def test_starts_only_after_registration(self):
        captured = {}

        def accept_registration(
            scenario_id,
            role,
            pid=None,
            timeout_seconds=5.0,
        ):
            # 등록 응답을 기다리는 동안 gate가 살아 있어야 한다.
            # 실제 작업은 시작 즉시 종료 코드 23으로 끝나는 프로그램이다.
            process = captured["process"]

            with self.assertRaises(subprocess.TimeoutExpired):
                process.wait(timeout=0.2)

            return {
                "role": role,
                "pid": pid,
                "start_time_ticks": 1,
                "registered_at": "test",
            }

        original_popen = subprocess.Popen

        def capture_process(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            captured["process"] = process
            return process

        with (
            patch(
                "scenarios.workers.subprocess.Popen",
                side_effect=capture_process,
            ),
            patch(
                "scenarios.workers.register_process_and_wait",
                side_effect=accept_registration,
            ),
        ):
            with registered_worker(
                "TEST",
                "test_worker",
                [sys.executable, "-c", "raise SystemExit(23)"],
            ) as (process, metadata):
                self.assertEqual(metadata["pid"], process.pid)

                # 확인 응답 후 START가 전달돼 실제 프로그램이 실행된다.
                self.assertEqual(process.wait(timeout=5), 23)

        self.assertIsNotNone(captured["process"].returncode)

    def test_registration_failure_reaps_child(self):
        captured = {}
        original_popen = subprocess.Popen

        def capture_process(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            captured["process"] = process
            return process

        with (
            patch(
                "scenarios.workers.subprocess.Popen",
                side_effect=capture_process,
            ),
            patch(
                "scenarios.workers.register_process_and_wait",
                side_effect=RuntimeError("등록 거절"),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "등록 거절"):
                with registered_worker(
                    "TEST",
                    "test_worker",
                    [sys.executable, "-c", "raise SystemExit(23)"],
                ):
                    self.fail("등록 실패 후에는 본문이 실행되면 안 됩니다.")

        # 등록에 실패해도 자식이 대기 상태로 남으면 안 된다.
        self.assertIsNotNone(captured["process"].returncode)


if __name__ == "__main__":
    unittest.main()
