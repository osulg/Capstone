"""허니팟 결과의 등록 PID·순서·경로 검증 검사."""

import copy
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(BACKEND))

from app.services.huntress_validation import (
    validate_honeypot_success,
)

from scenarios.huntress_config import HONEYPOT_FILES
from scenarios.huntress_honeypot_tasks import honeypot_paths


class HuntressValidationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

        root = Path(self.directory.name)
        mount = root / "mount"
        underlay = root / "underlay"
        workspace = "s02_" + "a" * 32

        mount_root, underlay_root = honeypot_paths(
            mount,
            underlay,
        )

        self.record = SimpleNamespace(
            workspace=SimpleNamespace(
                mount_path=str(mount / workspace),
                underlay_path=str(underlay / workspace),
            ),
            processes=[
                SimpleNamespace(
                    role="huntress_honeypot_check",
                    pid=201,
                    start_time_ticks=1001,
                ),
                SimpleNamespace(
                    role="huntress_honeypot_access",
                    pid=202,
                    start_time_ticks=1002,
                ),
            ],
        )

        self.result = {
            "honeypot_observation": {
                "access_started": True,
                "mount_root": str(mount_root),
                "underlay_root": str(underlay_root),
                "policy_verification": "not_checked",
                "targets": [
                    {
                        "name": name,
                        "mount_path": str(mount_root / name),
                        "underlay_path": str(underlay_root / name),
                    }
                    for name in HONEYPOT_FILES
                ],
            },
            "task_results": [],
        }

        for role, action, pid, target in (
            (
                "huntress_honeypot_check",
                "check",
                201,
                underlay_root,
            ),
            (
                "huntress_honeypot_access",
                "access",
                202,
                mount_root,
            ),
        ):
            self.result["task_results"].append(
                {
                    "role": role,
                    "pid": pid,
                    "action": action,
                    "status": "passed",
                    "planned": 5,
                    "attempted": 5,
                    "completed": 5,
                    "failure": None,
                    "operations": [
                        {
                            "name": name,
                            "path": str(target / name),
                            "outcome": (
                                "ready" if action == "check" else "permission_denied"
                            ),
                        }
                        for name in HONEYPOT_FILES
                    ],
                }
            )

    def test_valid_observation_is_accepted(self):
        validate_honeypot_success(self.result, self.record)

    def test_unregistered_access_pid_is_rejected(self):
        self.record.processes.pop()

        with self.assertRaisesRegex(ValueError, "등록되지 않은"):
            validate_honeypot_success(self.result, self.record)

    def test_wrong_task_order_is_rejected(self):
        self.result["task_results"].reverse()

        with self.assertRaisesRegex(ValueError, "작업 순서"):
            validate_honeypot_success(self.result, self.record)

    def test_wrong_target_path_is_rejected(self):
        self.result["task_results"][1]["operations"][0]["path"] = "/other/id_rsa"

        with self.assertRaisesRegex(ValueError, "대상 경로"):
            validate_honeypot_success(self.result, self.record)

    def test_incomplete_observation_cannot_pass(self):
        self.result["task_results"][1]["completed"] = 4

        with self.assertRaises(ValueError):
            validate_honeypot_success(self.result, self.record)

    def test_manager_cannot_claim_policy_success(self):
        self.result["honeypot_observation"]["policy_verification"] = "passed"

        with self.assertRaisesRegex(ValueError, "임의로 판정"):
            validate_honeypot_success(self.result, self.record)

    def test_read_success_is_only_an_observation(self):
        result = copy.deepcopy(self.result)

        for operation in result["task_results"][1]["operations"]:
            operation["outcome"] = "read_succeeded"

        # 접근이 성공한 결과도 관찰 기록으로는 유효하다.
        # 정책 보호 성공을 의미하지는 않는다.
        validate_honeypot_success(result, self.record)

        self.assertEqual(
            result["honeypot_observation"]["policy_verification"],
            "not_checked",
        )


if __name__ == "__main__":
    unittest.main()
