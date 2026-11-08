"""로그 삭제 관리자 흐름과 runner 결과 검증 검사."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(BACKEND))

from app.services.huntress_delete_validation import validate_delete_success
from app.services.runner import ScenarioRunner

from scenarios import s03_huntress as manager
from scenarios.catalog import get_scenario
from scenarios.huntress_config import DELETE_FILES
from scenarios.results import validate_result_details


class HuntressDeleteManagerTests(unittest.TestCase):
    def run_case(self, *, timeout=False, wrong_path=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mount = root / "mount"
            underlay = root / "underlay"
            mount.mkdir()
            underlay.mkdir()

            args = SimpleNamespace(
                mode="delete",
                mount=mount,
                underlay=underlay,
                worker_python=Path(sys.executable),
                work_dir_name="s03_" + "a" * 32,
                holdfs_pid=999,
                prepare_timeout=5.0,
                total_timeout=120.0,
            )
            processes = []

            @contextmanager
            def worker(scenario_id, role, command, **options):
                module_index = command.index("scenarios.huntress_delete_tasks")
                action = command[module_index + 1]
                target = Path(command[command.index("--root") + 1])

                metadata = {
                    "role": role,
                    "pid": 200 + len(processes),
                    "start_time_ticks": 1000 + len(processes),
                }
                processes.append(SimpleNamespace(**metadata))

                operations = []
                for name in DELETE_FILES:
                    item = {
                        "name": name,
                        "path": str(target / name),
                    }

                    if action == "inspect":
                        item["state"] = "matched"
                    else:
                        item["outcome"] = {
                            "prepare": "created",
                            "verify": "matched",
                            "delete": "permission_denied",
                        }[action]

                    operations.append(item)

                if wrong_path and action == "delete":
                    operations[0]["path"] = "/other/file"

                payload = {
                    "action": action,
                    "status": "passed",
                    "planned": len(DELETE_FILES),
                    "attempted": len(DELETE_FILES),
                    "completed": len(DELETE_FILES),
                    "failure": None,
                    "operations": operations,
                }

                process = Mock(stdin=None, returncode=0)
                if timeout and action == "delete":
                    process.communicate.side_effect = subprocess.TimeoutExpired(
                        command, 5
                    )
                else:
                    process.communicate.return_value = (
                        json.dumps(payload).encode("utf-8"),
                        None,
                    )

                yield process, metadata

            with (
                patch.object(manager.sys, "platform", "linux"),
                patch.object(manager, "check_health"),
                patch.object(manager, "emit_progress"),
                patch.object(
                    manager,
                    "register_process_and_wait",
                    return_value={
                        "role": "huntress_manager",
                        "pid": os.getpid(),
                        "start_time_ticks": 1,
                    },
                ),
                patch.object(
                    manager,
                    "registered_worker",
                    side_effect=worker,
                ),
            ):
                report = manager.run(args)

            record = SimpleNamespace(
                pid=os.getpid(),
                mode="delete",
                workspace=SimpleNamespace(
                    mount_path=str(mount / args.work_dir_name),
                    underlay_path=str(underlay / args.work_dir_name),
                ),
                processes=processes,
            )

            return report, record

    def test_complete_flow_passes_runner_validation(self):
        report, record = self.run_case()

        self.assertEqual(report["status"], "passed")
        self.assertIsNotNone(report["finished_at"])
        self.assertEqual(
            [step["name"] for step in report["steps"]],
            [
                "PRECHECK",
                "PREPARE",
                "VERIFY_READY",
                "DELETE",
                "INSPECT_MOUNT",
                "INSPECT_UNDERLAY",
            ],
        )
        self.assertEqual(
            [process.role for process in record.processes],
            [
                "huntress_delete_prepare",
                "huntress_delete_verify_mount",
                "huntress_delete_verify_underlay",
                "huntress_delete",
                "huntress_delete_inspect_mount",
                "huntress_delete_inspect_underlay",
            ],
        )

        observation = report["delete_observation"]
        self.assertEqual(observation["unlink_succeeded"], 0)
        self.assertEqual(observation["permission_denied"], 12)
        self.assertEqual(
            observation["policy_verification"],
            "not_checked",
        )

        validate_result_details(report)
        validate_delete_success(report, record)

        # runnerが使用する削除モードの段階定義で検証する。
        scenario = get_scenario("S03")
        mode = next(item for item in scenario.modes if item.id == "delete")
        effective_scenario = replace(scenario, steps=mode.steps)

        ScenarioRunner._validate_result(
            report,
            record,
            effective_scenario,
        )

    def test_delete_timeout_preserves_started_state(self):
        report, record = self.run_case(timeout=True)

        self.assertEqual(report["status"], "timed_out")
        self.assertTrue(report["delete_observation"]["delete_started"])
        self.assertEqual(report["steps"][-1]["name"], "DELETE")
        self.assertEqual(report["steps"][-1]["status"], "failed")
        self.assertEqual(len(record.processes), 4)

        validate_result_details(report)

    def test_wrong_child_path_is_rejected(self):
        report, record = self.run_case(wrong_path=True)

        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["steps"][-1]["name"], "DELETE")
        self.assertEqual(len(record.processes), 4)

        # 검증에 실패한 삭제 결과는 정상 작업 목록에 포함하지 않는다.
        self.assertEqual(len(report["task_results"]), 3)
        validate_result_details(report)


if __name__ == "__main__":
    unittest.main()
