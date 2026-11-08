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

    def test_icefire_command_requests_full_execution(self):
        spec = get_execution("S01", "scenarios.s01_icefire")
        self.assertIsNotNone(spec)

        command = spec.build_command(
            mount=Path("/runtime/mount"),
            underlay=Path("/runtime/underlay"),
            work_dir_name="s01_" + "a" * 32,
        )

        self.assertEqual(command.count("--run-attack"), 1)
        self.assertIn("--wait-registration-ack", command)
        self.assertEqual(
            command[command.index("-m") + 1],
            "scenarios.s01_icefire",
        )

    def test_other_simulators_are_not_allowed_yet(self):
        for scenario_id, module in (
            ("S02", "scenarios.s02_darkradiation"),
            ("S04", "scenarios.s04_akira"),
        ):
            with self.subTest(scenario_id=scenario_id):
                self.assertIsNone(get_execution(scenario_id, module))

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

    def test_huntress_execution_contract(self):
        spec = get_execution("S03", "scenarios.s03_huntress")
        self.assertIsNotNone(spec)
        self.assertEqual(spec.timeout_seconds, 120.0)
        self.assertEqual(
            spec.workspace_name("test-run"),
            "s03_test-run",
        )

        command = spec.build_command(
            mount=Path("/runtime/mount"),
            underlay=Path("/runtime/underlay"),
            work_dir_name="s03_" + "a" * 32,
        )

        self.assertEqual(
            command[command.index("-m") + 1],
            "scenarios.s03_huntress",
        )
        self.assertEqual(
            float(command[command.index("--total-timeout") + 1]),
            120.0,
        )
        self.assertNotIn("--run-attack", command)


if __name__ == "__main__":
    unittest.main()
