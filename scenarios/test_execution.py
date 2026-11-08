"""시나리오 실행 허용 목록과 명령 구성 검사."""

import sys
import unittest
from pathlib import Path

from scenarios.execution import get_execution


class ExecutionTests(unittest.TestCase):
    def test_rejects_unknown_module(self):
        self.assertIsNone(get_execution("S01", "scenarios.not_allowed"))
        self.assertIsNone(get_execution("S01", None))

    def test_rejects_wrong_scenario_id(self):
        self.assertIsNone(get_execution("S02", "scenarios.s01_normal"))

    def test_unimplemented_simulator_is_not_allowed(self):
        self.assertIsNone(get_execution("S01", "scenarios.s01_icefire"))

    def test_normal_command_preserves_execution_contract(self):
        spec = get_execution("S01", "scenarios.s01_normal")
        self.assertIsNotNone(spec)

        name = spec.workspace_name("test-run")
        self.assertEqual(name, "s01_test-run")

        mount = Path("/runtime/mount")
        underlay = Path("/runtime/underlay")

        self.assertEqual(
            spec.build_command(
                mount=mount,
                underlay=underlay,
                work_dir_name=name,
            ),
            [
                sys.executable,
                "-u",
                "-m",
                "scenarios.s01_normal",
                "--wait-registration-ack",
                "--mount",
                str(mount),
                "--underlay",
                str(underlay),
                "--work-dir-name",
                name,
            ],
        )


if __name__ == "__main__":
    unittest.main()
