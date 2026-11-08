"""로그 삭제 사후 조회의 파일 집계와 오류 처리 검사."""

import json
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(BACKEND))

from app.services.huntress_delete_observation import observe_deleted_files

from scenarios.huntress_config import DELETE_FILES


class HuntressDeleteObservationTests(unittest.TestCase):
    def setUp(self):
        self.record = SimpleNamespace(
            scenario_id="S03",
            mode="delete",
            run_id="test",
            workspace=SimpleNamespace(
                name="s03_test",
                mount_path="/runtime/mount/s03_test",
                underlay_path="/runtime/underlay/s03_test",
            ),
        )

    def make_response(self, root, *, missing=0):
        operations = [
            {
                "name": name,
                "path": str(Path(root) / name),
                "state": "missing" if index < missing else "matched",
            }
            for index, name in enumerate(DELETE_FILES)
        ]

        payload = {
            "action": "inspect",
            "status": "passed",
            "planned": len(DELETE_FILES),
            "attempted": len(DELETE_FILES),
            "completed": len(DELETE_FILES),
            "failure": None,
            "operations": operations,
        }

        return SimpleNamespace(
            stdout=json.dumps(payload).encode("utf-8"),
        )

    def observe(self, *, cleanup_confirmed=True):
        return observe_deleted_files(
            self.record,
            cleanup_confirmed=cleanup_confirmed,
        )

    def test_partial_file_loss_is_reported(self):
        responses = [
            self.make_response(
                self.record.workspace.mount_path,
                missing=3,
            ),
            self.make_response(
                self.record.workspace.underlay_path,
                missing=2,
            ),
        ]

        with patch(
            "app.services.huntress_delete_observation.subprocess.run",
            side_effect=responses,
        ):
            result = self.observe()

        self.assertEqual(result["status"], "observed")
        self.assertEqual(result["counts"]["mount"]["missing"], 3)
        self.assertEqual(result["counts"]["underlay"]["missing"], 2)
        self.assertEqual(result["counts"]["mount"]["matched"], 9)
        self.assertEqual(result["counts"]["underlay"]["matched"], 10)
        self.assertEqual(result["issues"], [])

    def test_mount_timeout_does_not_prevent_underlay_inspection(self):
        responses = [
            subprocess.TimeoutExpired(cmd=["inspect"], timeout=7),
            self.make_response(self.record.workspace.underlay_path),
        ]

        with patch(
            "app.services.huntress_delete_observation.subprocess.run",
            side_effect=responses,
        ) as inspect:
            result = self.observe()

        self.assertEqual(inspect.call_count, 2)
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["counts"]["mount"]["unreadable"], 12)
        self.assertEqual(result["counts"]["underlay"]["matched"], 12)
        self.assertEqual(len(result["issues"]), 1)

    def test_wrong_file_path_is_rejected(self):
        response = self.make_response(self.record.workspace.mount_path)
        payload = json.loads(response.stdout)
        payload["operations"][0]["path"] = "/other/file"
        response.stdout = json.dumps(payload).encode("utf-8")

        with patch(
            "app.services.huntress_delete_observation.subprocess.run",
            side_effect=[
                response,
                self.make_response(self.record.workspace.underlay_path),
            ],
        ):
            result = self.observe()

        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["counts"]["mount"]["unreadable"], 12)
        self.assertTrue(result["issues"])

    def test_unreadable_file_prevents_complete_observation(self):
        response = self.make_response(self.record.workspace.mount_path)
        payload = json.loads(response.stdout)
        payload["operations"][0]["state"] = "unreadable"
        response.stdout = json.dumps(payload).encode("utf-8")

        with patch(
            "app.services.huntress_delete_observation.subprocess.run",
            side_effect=[
                response,
                self.make_response(self.record.workspace.underlay_path),
            ],
        ):
            result = self.observe()

        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["counts"]["mount"]["unreadable"], 1)

    def test_unconfirmed_cleanup_prevents_inspection(self):
        with patch(
            "app.services.huntress_delete_observation.subprocess.run",
        ) as inspect:
            result = self.observe(cleanup_confirmed=False)

        inspect.assert_not_called()
        self.assertEqual(result["status"], "unknown")

    def test_wrong_workspace_prevents_inspection(self):
        self.record.workspace.name = "s03_other"

        with patch(
            "app.services.huntress_delete_observation.subprocess.run",
        ) as inspect:
            result = self.observe()

        inspect.assert_not_called()
        self.assertEqual(result["status"], "unknown")

    def test_cancelled_run_still_inspects_files_after_cleanup(self):
        self.record.status = "cancelled"

        with patch(
            "app.services.huntress_delete_observation.subprocess.run",
            side_effect=[
                self.make_response(self.record.workspace.mount_path),
                self.make_response(self.record.workspace.underlay_path),
            ],
        ) as inspect:
            result = self.observe()

        self.assertEqual(inspect.call_count, 2)
        self.assertEqual(result["status"], "observed")


if __name__ == "__main__":
    unittest.main()
