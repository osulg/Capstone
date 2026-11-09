"""실제 웹 시나리오 목록과 미연동 실행 거절 검사."""

import importlib.util
import sys
import unittest
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(BACKEND))

from scenarios.catalog import get_scenario, list_scenarios

HAS_PYDANTIC = importlib.util.find_spec("pydantic") is not None

if HAS_PYDANTIC:
    from app.schemas.run import RunRequest
    from app.services.runner import (
        ScenarioRunner,
        ScenarioUnavailableError,
    )
    from pydantic import ValidationError


class ScenarioCatalogTests(unittest.TestCase):
    def test_catalog_contains_three_final_scenarios(self):
        scenarios = list_scenarios()

        self.assertEqual(
            [(item["id"], item["name"]) for item in scenarios],
            [
                ("S01", "IceFire"),
                ("S02", "Huntress"),
                ("S03", "Akira"),
            ],
        )

    def test_all_final_scenarios_are_enabled(self):
        for item in list_scenarios():
            with self.subTest(scenario_id=item["id"]):
                self.assertTrue(item["enabled"])
                self.assertIsNone(item["disabled_reason"])

    def test_huntress_delete_mode_is_disabled(self):
        scenario = get_scenario("S02")

        self.assertEqual(
            [(mode.id, mode.enabled) for mode in scenario.modes],
            [("read", True), ("honeypot", True), ("delete", False)],
        )
        self.assertTrue(scenario.modes[2].disabled_reason)

    def test_icefire_module_and_steps_are_connected(self):
        scenario = get_scenario("S01")

        self.assertEqual(scenario.module, "scenarios.s01_icefire")
        self.assertEqual(
            [name for step in scenario.steps for name in step.operation_names],
            ["PRECHECK", "PREPARE", "VERIFY_READY", "ACTION"],
        )


@unittest.skipUnless(
    HAS_PYDANTIC,
    "백엔드 Pydantic 환경이 필요합니다.",
)
class ScenarioRequestTests(unittest.TestCase):
    def test_request_accepts_current_ids(self):
        for scenario_id in ("S01", "S02", "S03"):
            with self.subTest(scenario_id=scenario_id):
                payload = {"scenario_id": scenario_id}

                if scenario_id == "S02":
                    payload["mode"] = "read"
                elif scenario_id == "S03":
                    payload["mode"] = "head"

                request = RunRequest(**payload)
                self.assertEqual(request.scenario_id, scenario_id)

    def test_request_rejects_removed_id(self):
        for scenario_id in ("S04", "S05"):
            with self.subTest(scenario_id=scenario_id):
                with self.assertRaises(ValidationError):
                    RunRequest(scenario_id=scenario_id)


@unittest.skipUnless(
    HAS_PYDANTIC,
    "백엔드 Pydantic 환경이 필요합니다.",
)
class ScenarioAvailabilityTests(unittest.IsolatedAsyncioTestCase):
    async def test_removed_scenarios_do_not_schedule_execution(self):
        runner = ScenarioRunner()

        try:
            for scenario_id in ("S04", "S05"):
                with self.subTest(scenario_id=scenario_id):
                    with self.assertRaises(ScenarioUnavailableError):
                        runner.start(scenario_id)

            self.assertIsNone(runner._active_task)
            self.assertEqual(runner._runs, {})
        finally:
            await runner.close()
