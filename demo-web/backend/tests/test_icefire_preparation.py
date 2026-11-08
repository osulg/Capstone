"""IceFire 준비 관리자의 등록·시작·실패·자식 정리 연결 검사.

FUSE와 실제 자식 대신 임시 디렉터리와 가짜 프로세스를 사용한다.
registered_worker의 등록 승인 및 START 제어 로직은 실제로 실행한다.
"""

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

from scenarios import s01_icefire
from scenarios.results import validate_result_details
from scenarios.icefire_config import FILE_COUNT, expected_operations


class StartPipe:
    def __init__(self, role, events):
        self.role = role
        self.events = events
        self.closed = False

    def write(self, data):
        if self.closed:
            raise ValueError("닫힌 시작 통로입니다.")
        self.events.append(("start", self.role, data))
        return len(data)

    def flush(self):
        pass

    def close(self):
        self.closed = True


class IceFirePreparationTests(unittest.TestCase):
    def run_case(
        self,
        *,
        reject=None,
        returncode=0,
        timeout_role=None,
        malformed=False,
        reported_timeout=False,
        run_attack=False,
    ):
        events = []
        children = []

        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            mount = root / "mount"
            underlay = root / "underlay"
            mount.mkdir()
            underlay.mkdir()
            workdir = mount / ("s01_" + "a" * 32)
            args = SimpleNamespace(
                mount=mount,
                underlay=underlay,
                work_dir_name=workdir.name,
                holdfs_pid=999,
                prepare_timeout=0.1,
                attack_timeout=0.2,
                worker_python=Path(sys.executable),
                wait_registration_ack=True,
                run_attack=run_attack,
            )

            def manager_registration(scenario_id, role):
                self.assertFalse(workdir.exists())
                events.append(("manager_registration", role))
                if reject == "manager":
                    raise RuntimeError("관리자 등록 거절")
                return {"role": role, "pid": 100, "start_time_ticks": 1}

            def spawn(command, **kwargs):
                self.assertTrue(workdir.is_dir())
                self.assertFalse(kwargs["start_new_session"])
                action = command[command.index("scenarios.icefire_tasks") + 1]
                task_command = command[command.index("--") + 1:]
                self.assertEqual(task_command[0], str(Path(sys.executable).absolute()))
                self.assertEqual(command[command.index("--files") + 1], str(FILE_COUNT))
                limit = 0.2 if action == "attack" else 0.1
                self.assertEqual(float(command[command.index("--timeout") + 1]), limit)
                self.assertIn(action, ("prepare", "verify", "attack"))
                self.assertEqual(command[command.index("--workdir") + 1], str(workdir))
                role = f"icefire_{action}"
                events.append(("spawn", role))
                child = Mock()
                child.pid = 200 + len(children)
                child.stdin = StartPipe(role, events)
                child.start_pipe = child.stdin
                child.poll.return_value = None
                child.wait.return_value = returncode if action == "prepare" else 0
                child.returncode = returncode if action == "prepare" else 0

                def communicate(timeout):
                    self.assertIsNone(child.stdin)
                    self.assertAlmostEqual(timeout, limit + 1.0)
                    if role == timeout_role:
                        raise subprocess.TimeoutExpired(command, timeout)
                    failed = action == "prepare" and (
                        returncode != 0 or reported_timeout
                    )
                    if failed:
                        child.returncode = 1
                    planned = expected_operations(action)
                    payload = {
                        "action": action,
                        "status": ("timed_out" if reported_timeout else "failed")
                        if failed
                        else "passed",
                        "planned": planned,
                        "attempted": 3 if failed else planned,
                        "completed": 2 if failed else planned,
                        "failure": {
                            "operation": action,
                            "path": str(workdir / "doc_002.xlsx"),
                            "errno": None if reported_timeout else 13,
                            "message": "테스트용 작업 실패",
                        }
                        if failed
                        else None,
                    }
                    return (
                        b"invalid JSON" if malformed else json.dumps(payload).encode(),
                        None,
                    )

                child.communicate.side_effect = communicate
                children.append(child)
                return child

            def child_registration(scenario_id, role, pid, timeout_seconds):
                self.assertFalse(any(event[:2] == ("start", role) for event in events))
                events.append(("child_registration", role))
                if reject == role:
                    raise RuntimeError("자식 등록 거절")
                if reject == "eof":
                    raise RuntimeError("runner의 등록 응답 통로가 종료됐습니다.")
                return {"role": role, "pid": pid, "start_time_ticks": 2}

            stack.enter_context(patch.object(s01_icefire.sys, "platform", "linux"))
            stack.enter_context(patch.object(s01_icefire, "check_health"))
            stack.enter_context(patch.object(s01_icefire, "emit_progress"))
            stack.enter_context(
                patch.object(
                    s01_icefire,
                    "register_process_and_wait",
                    side_effect=manager_registration,
                )
            )
            stack.enter_context(
                patch(
                    "scenarios.workers.register_process_and_wait",
                    side_effect=child_registration,
                )
            )
            stack.enter_context(
                patch(
                    "scenarios.workers.subprocess.Popen",
                    side_effect=spawn,
                )
            )

            report = s01_icefire.run(args)
            validate_result_details(report)
            self.assertEqual(report["execution_scope"], "full" if run_attack else "prepare_only")
            started = ("start", "icefire_attack", b"START\n") in events
            self.assertEqual(report["attack_started"], started)
            self.assertIsNotNone(report["finished_at"])
            for child in children:
                self.assertTrue(child.start_pipe.closed)
                child.terminate.assert_called_once()
                self.assertGreaterEqual(child.wait.call_count, 1)
            return report, events, children, workdir.exists()

    def test_success_registers_before_start_and_prepares_before_verify(self):
        report, events, children, exists = self.run_case()
        self.assertEqual(report["status"], "passed")
        self.assertTrue(exists)
        self.assertEqual(len(children), 2)
        self.assertEqual(
            events,
            [
                ("manager_registration", "icefire_manager"),
                ("spawn", "icefire_prepare"),
                ("child_registration", "icefire_prepare"),
                ("start", "icefire_prepare", b"START\n"),
                ("spawn", "icefire_verify"),
                ("child_registration", "icefire_verify"),
                ("start", "icefire_verify", b"START\n"),
            ],
        )
        self.assertEqual(
            [step["name"] for step in report["steps"]],
            ["PRECHECK", "PREPARE", "VERIFY_READY"],
        )

    def test_manager_rejection_does_not_create_workspace(self):
        report, _, children, exists = self.run_case(reject="manager")
        self.assertEqual(report["status"], "failed")
        self.assertFalse(exists)
        self.assertEqual(children, [])

    def test_child_rejection_or_eof_never_sends_start(self):
        for rejection in ("icefire_prepare", "eof"):
            with self.subTest(rejection=rejection):
                report, events, children, _ = self.run_case(reject=rejection)
                self.assertEqual(report["status"], "failed")
                self.assertEqual(len(children), 1)
                self.assertFalse(any(event[0] == "start" for event in events))

    def test_prepare_failure_does_not_start_verification(self):
        report, _, children, _ = self.run_case(returncode=3)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(len(children), 1)
        self.assertEqual(report["steps"][-1]["name"], "PREPARE")

    def test_verification_registration_rejection_does_not_start_verification(self):
        report, events, children, _ = self.run_case(reject="icefire_verify")
        self.assertEqual(report["status"], "failed")
        self.assertEqual(len(children), 2)
        self.assertNotIn(("start", "icefire_verify", b"START\n"), events)

    def test_worker_timeout_is_reported_and_child_is_reaped(self):
        for role in ("icefire_prepare", "icefire_verify"):
            with self.subTest(role=role):
                report, _, children, _ = self.run_case(timeout_role=role)
                self.assertEqual(report["status"], "timed_out")
                self.assertEqual(report["termination_reason"], "deadline_exceeded")
                self.assertEqual(children[-1].wait.call_count, 1)

    def test_success_preserves_child_counts(self):
        report, _, _, _ = self.run_case()
        self.assertEqual(
            [item["action"] for item in report["task_results"]], ["prepare", "verify"]
        )
        self.assertTrue(all(item["completed"] == 11 for item in report["task_results"]))

    def test_child_reported_timeout_preserves_partial_details(self):
        report, _, children, _ = self.run_case(reported_timeout=True)
        self.assertEqual(report["status"], "timed_out")
        self.assertEqual(len(children), 1)
        self.assertEqual(report["task_results"][0]["completed"], 2)
        self.assertEqual(
            report["task_results"][0]["failure"]["message"], "테스트용 작업 실패"
        )

    def test_malformed_json_stops_before_verification(self):
        report, _, children, _ = self.run_case(malformed=True)
        self.assertEqual(report["status"], "failed")
        self.assertIn("결과 형식 오류", report["steps"][-1]["error"])
        self.assertEqual(len(children), 1)
        self.assertEqual(report["task_results"], [])


    def test_full_execution_starts_attack_after_verification(self):
        report, events, children, _ = self.run_case(run_attack=True)
        self.assertEqual(report["status"], "passed")
        self.assertTrue(report["attack_started"])
        self.assertEqual(len(children), 3)
        self.assertLess(
            events.index(("start", "icefire_verify", b"START\n")),
            events.index(("child_registration", "icefire_attack")),
        )
        self.assertEqual(report["task_results"][-1]["completed"], 32)
        self.assertEqual(report["steps"][-1]["name"], "ACTION")

    def test_prepare_failure_prevents_requested_attack(self):
        report, _, children, _ = self.run_case(run_attack=True, returncode=3)
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["attack_started"])
        self.assertEqual(len(children), 1)

    def test_attack_registration_rejection_prevents_start(self):
        report, _, _, _ = self.run_case(run_attack=True, reject="icefire_attack")
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["attack_started"])

    def test_attack_wait_timeout_preserves_started_flag(self):
        report, _, _, _ = self.run_case(run_attack=True, timeout_role="icefire_attack")
        self.assertEqual(report["status"], "timed_out")
        self.assertTrue(report["attack_started"])


if __name__ == "__main__":
    unittest.main()
