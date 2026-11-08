"""로그 삭제 결과의 PID·순서·파일 상태 검증 검사."""

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(BACKEND))

from app.services.huntress_delete_validation import validate_delete_success

from scenarios.huntress_config import DELETE_FILES


class HuntressDeleteValidationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)

        root = Path(directory.name)
        mount = root / "mount" / "s03_test"
        underlay = root / "underlay" / "s03_test"

        definitions = (
            ("huntress_delete_prepare", "prepare", mount),
            ("huntress_delete_verify_mount", "verify", mount),
            ("huntress_delete_verify_underlay", "verify", underlay),
            ("huntress_delete", "delete", mount),
            ("huntress_delete_inspect_mount", "inspect", mount),
            ("huntress_delete_inspect_underlay", "inspect", underlay),
        )

        tasks = []
        processes = []

        for index, (role, action, target) in enumerate(definitions):
            pid = 200 + index
            processes.append(
                SimpleNamespace(
                    role=role,
                    pid=pid,
                    start_time_ticks=1000 + index,
                )
            )

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

            tasks.append(
                {
                    "role": role,
                    "pid": pid,
                    "action": action,
                    "status": "passed",
                    "planned": len(DELETE_FILES),
                    "attempted": len(DELETE_FILES),
                    "completed": len(DELETE_FILES),
                    "failure": None,
                    "operations": operations,
                }
            )

        self.record = SimpleNamespace(
            workspace=SimpleNamespace(
                mount_path=str(mount),
                underlay_path=str(underlay),
            ),
            processes=processes,
        )
        self.result = {
            "task_results": tasks,
            "delete_observation": {
                "delete_started": True,
                "policy_verification": "not_checked",
                "unlink_succeeded": 0,
                "permission_denied": len(DELETE_FILES),
                "files": [
                    {
                        "name": name,
                        "mount": "matched",
                        "underlay": "matched",
                    }
                    for name in DELETE_FILES
                ],
            },
        }

    def test_complete_observation_is_accepted(self):
        validate_delete_success(self.result, self.record)

    def test_partial_deletion_is_preserved_as_observation(self):
        # 일부 삭제가 성공해도 관찰 결과로는 유효하다.
        # 전체 보존이나 보호 성공을 의미하지 않는다.
        tasks = self.result["task_results"]
        observation = self.result["delete_observation"]

        tasks[3]["operations"][0]["outcome"] = "unlink_succeeded"
        tasks[4]["operations"][0]["state"] = "missing"
        tasks[5]["operations"][0]["state"] = "missing"

        observation["unlink_succeeded"] = 1
        observation["permission_denied"] = len(DELETE_FILES) - 1
        observation["files"][0].update(
            mount="missing",
            underlay="missing",
        )

        validate_delete_success(self.result, self.record)

    def test_unregistered_pid_is_rejected(self):
        self.result["task_results"][3]["pid"] = 999

        with self.assertRaises(ValueError):
            validate_delete_success(self.result, self.record)

    def test_missing_process_identity_is_rejected(self):
        self.record.processes[3].start_time_ticks = None

        with self.assertRaises(ValueError):
            validate_delete_success(self.result, self.record)

    def test_wrong_task_order_is_rejected(self):
        self.result["task_results"].reverse()

        with self.assertRaises(ValueError):
            validate_delete_success(self.result, self.record)

    def test_wrong_file_path_is_rejected(self):
        self.result["task_results"][3]["operations"][0]["path"] = "/other/file"

        with self.assertRaises(ValueError):
            validate_delete_success(self.result, self.record)

    def test_incomplete_task_is_rejected(self):
        self.result["task_results"][3]["completed"] -= 1

        with self.assertRaises(ValueError):
            validate_delete_success(self.result, self.record)

    def test_incorrect_summary_count_is_rejected(self):
        self.result["delete_observation"]["unlink_succeeded"] = 1

        with self.assertRaises(ValueError):
            validate_delete_success(self.result, self.record)

    def test_incorrect_file_summary_is_rejected(self):
        self.result["delete_observation"]["files"][0]["underlay"] = "missing"

        with self.assertRaises(ValueError):
            validate_delete_success(self.result, self.record)

    def test_manager_cannot_claim_policy_success(self):
        self.result["delete_observation"]["policy_verification"] = "passed"

        with self.assertRaises(ValueError):
            validate_delete_success(self.result, self.record)


if __name__ == "__main__":
    unittest.main()
