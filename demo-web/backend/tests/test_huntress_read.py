"""Huntress 일반 읽기 관리자의 실행 순서와 실패 처리 검사."""

import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(BACKEND))

from scenarios import s03_huntress
from scenarios.huntress_config import READ_FILES
from scenarios.results import validate_result_details


class StartPipe:
    """START 전달 여부를 기록하는 가짜 입력 통로."""

    def __init__(self, events, pid):
        self.events = events
        self.pid = pid
        self.closed = False

    def write(self, data):
        if self.closed:
            raise ValueError("이미 닫힌 통로입니다.")

        self.events.append(("start", self.pid, data))
        return len(data)

    def flush(self):
        pass

    def close(self):
        self.closed = True


class HuntressReadTests(unittest.TestCase):
    def run_case(
        self,
        *,
        mode="read",
        reject_role=None,
        fail_role=None,
        timeout_role=None,
        malformed_role=None,
    ):
        events = []
        children = []

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mount = root / "mount"
            underlay = root / "underlay"
            mount.mkdir()
            underlay.mkdir()

            workspace = "s03_" + "a" * 32
            workdir = mount / workspace

            args = SimpleNamespace(
                mode=mode,
                mount=mount,
                underlay=underlay,
                worker_python=Path(sys.executable),
                work_dir_name=workspace,
                holdfs_pid=999,
                prepare_timeout=1.0,
                total_timeout=120.0,
                wait_registration_ack=True,
            )

            def register_manager(
                scenario_id,
                role,
                timeout_seconds,
            ):
                self.assertEqual(scenario_id, "S03")
                self.assertFalse(workdir.exists())
                events.append(("manager", role))

                if reject_role == role:
                    raise RuntimeError("관리자 등록 거절")

                return {
                    "role": role,
                    "pid": 100,
                    "start_time_ticks": 1,
                }

            def spawn(command, **kwargs):
                self.assertTrue(workdir.is_dir())
                self.assertFalse(kwargs["start_new_session"])
                self.assertEqual(kwargs["stdout"], subprocess.PIPE)

                action = command[command.index("scenarios.huntress_tasks") + 1]
                target = command[command.index("--workdir") + 1]

                child = Mock()
                child.pid = 200 + len(children)
                child.returncode = None
                child.role = None
                child.start_pipe = StartPipe(events, child.pid)
                child.stdin = child.start_pipe

                child.poll.side_effect = lambda: child.returncode

                def terminate():
                    child.returncode = -15

                child.terminate.side_effect = terminate
                child.wait.return_value = 0

                def communicate(timeout):
                    self.assertIsNone(child.stdin)
                    self.assertTrue(child.start_pipe.closed)
                    events.append(("communicate", child.role, action, target))

                    if child.role == timeout_role:
                        raise subprocess.TimeoutExpired(
                            command,
                            timeout,
                        )

                    failed = child.role == fail_role
                    child.returncode = 1 if failed else 0

                    operations = []
                    for index, name in enumerate(READ_FILES):
                        operation_failed = failed and index == 0

                        item = {
                            "name": name,
                            "path": str(Path(target) / name),
                            "status": ("failed" if operation_failed else "passed"),
                        }

                        if action in ("verify", "read"):
                            item["content_matched"] = True

                        operations.append(item)

                    payload = {
                        "action": action,
                        "status": "failed" if failed else "passed",
                        "planned": 6,
                        "attempted": 6,
                        "completed": 5 if failed else 6,
                        "failure": {
                            "operation": action,
                            "path": str(Path(target) / READ_FILES[0]),
                            "errno": 13,
                            "message": "테스트용 접근 거절",
                        }
                        if failed
                        else None,
                        "operations": operations,
                    }

                    if child.role == malformed_role:
                        return b"invalid JSON", None

                    return json.dumps(payload).encode(), None

                child.communicate.side_effect = communicate
                children.append(child)
                return child

            def register_child(
                scenario_id,
                role,
                pid,
                timeout_seconds,
            ):
                self.assertEqual(scenario_id, "S03")

                child = next(item for item in children if item.pid == pid)
                child.role = role

                # 등록 승인 전에 START가 전달되면 안 된다.
                self.assertFalse(
                    any(item[0] == "start" and item[1] == pid for item in events)
                )
                events.append(("registered", role, pid))

                if role == reject_role:
                    raise RuntimeError("자식 등록 거절")

                return {
                    "role": role,
                    "pid": pid,
                    "start_time_ticks": 2,
                }

            with ExitStack() as stack:
                stack.enter_context(
                    patch.object(
                        s03_huntress.sys,
                        "platform",
                        "linux",
                    )
                )
                stack.enter_context(patch.object(s03_huntress, "check_health"))
                stack.enter_context(patch.object(s03_huntress, "emit_progress"))
                stack.enter_context(
                    patch.object(
                        s03_huntress,
                        "register_process_and_wait",
                        side_effect=register_manager,
                    )
                )
                stack.enter_context(
                    patch(
                        "scenarios.workers.register_process_and_wait",
                        side_effect=register_child,
                    )
                )
                stack.enter_context(
                    patch(
                        "scenarios.workers.subprocess.Popen",
                        side_effect=spawn,
                    )
                )

                report = s03_huntress.run(args)

            validate_result_details(report)
            self.assertIsNotNone(report["finished_at"])
            self.assertEqual(
                report["detection_verification"],
                "not_checked",
            )

            for child in children:
                self.assertTrue(child.start_pipe.closed)
                child.wait.assert_called()

                if child.communicate.call_count == 0:
                    child.terminate.assert_called_once()

            return report, events, children

    def test_successful_execution_order(self):
        report, events, children = self.run_case()

        self.assertEqual(report["status"], "passed")
        self.assertEqual(len(children), 5)

        self.assertEqual(
            [event[1] for event in events if event[0] == "communicate"],
            [
                "huntress_prepare",
                "huntress_verify_ready",
                "huntress_read",
                "huntress_verify_mount",
                "huntress_verify_underlay",
            ],
        )

        self.assertEqual(
            [step["name"] for step in report["steps"]],
            [
                "PRECHECK",
                "PREPARE",
                "VERIFY_READY",
                "READ",
                "VERIFY_MOUNT",
                "VERIFY_UNDERLAY",
            ],
        )

        self.assertEqual(
            report["content_verification"]["status"],
            "passed",
        )

        # 모든 자식은 등록 승인 이후 시작된다.
        for child in children:
            registered = events.index(("registered", child.role, child.pid))
            started = events.index(("start", child.pid, b"START\n"))
            self.assertLess(registered, started)

        targets = [event[3] for event in events if event[0] == "communicate"]

        self.assertIn("mount", Path(targets[0]).parts)
        self.assertIn("underlay", Path(targets[-1]).parts)

    def test_prepare_failure_prevents_read(self):
        report, _, children = self.run_case(fail_role="huntress_prepare")

        self.assertEqual(report["status"], "failed")
        self.assertEqual(len(children), 1)
        self.assertEqual(
            report["content_verification"]["status"],
            "not_checked",
        )

    def test_registration_rejection_prevents_start(self):
        report, events, children = self.run_case(reject_role="huntress_prepare")

        self.assertEqual(report["status"], "failed")
        self.assertEqual(len(children), 1)

        self.assertFalse(any(event[0] == "start" for event in events))

    def test_read_failure_prevents_content_verification(self):
        report, _, children = self.run_case(fail_role="huntress_read")

        self.assertEqual(report["status"], "failed")
        self.assertEqual(len(children), 3)
        self.assertEqual(
            report["task_results"][-1]["completed"],
            5,
        )

    def test_timeout_terminates_and_reaps_child(self):
        report, _, children = self.run_case(timeout_role="huntress_read")

        self.assertEqual(report["status"], "timed_out")
        self.assertEqual(
            report["termination_reason"],
            "deadline_exceeded",
        )

        children[-1].terminate.assert_called_once()
        children[-1].wait.assert_called()

    def test_malformed_json_stops_following_tasks(self):
        report, _, children = self.run_case(malformed_role="huntress_prepare")

        self.assertEqual(report["status"], "failed")
        self.assertEqual(len(children), 1)
        self.assertEqual(report["task_results"], [])

    def test_other_modes_are_not_executed(self):
        for mode in ("honeypot", "delete"):
            with self.subTest(mode=mode):
                report, _, children = self.run_case(mode=mode)

                self.assertEqual(report["status"], "failed")
                self.assertEqual(children, [])


if __name__ == "__main__":
    unittest.main()
