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
    def test_catalog_contains_new_four_scenarios(self):
        scenarios = list_scenarios()

        self.assertEqual(
            [(item["id"], item["name"]) for item in scenarios],
            [
                ("S01", "IceFire 랜섬웨어"),
                ("S02", "DarkRadiation 랜섬웨어"),
                ("S03", "Huntress"),
                ("S04", "Akira"),
            ],
        )

    def test_only_icefire_is_enabled(self):
        for item in list_scenarios():
            with self.subTest(scenario_id=item["id"]):
                if item["id"] == "S01":
                    self.assertTrue(item["enabled"])
                    self.assertIsNone(item["disabled_reason"])
                else:
                    self.assertFalse(item["enabled"])
                    self.assertTrue(item["disabled_reason"])

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
        for scenario_id in ("S01", "S02", "S03", "S04"):
            with self.subTest(scenario_id=scenario_id):
                self.assertEqual(
                    RunRequest(scenario_id=scenario_id).scenario_id,
                    scenario_id,
                )

    def test_request_rejects_removed_id(self):
        with self.assertRaises(ValidationError):
            RunRequest(scenario_id="S05")


@unittest.skipUnless(
    HAS_PYDANTIC,
    "백엔드 Pydantic 환경이 필요합니다.",
)
class ScenarioAvailabilityTests(unittest.IsolatedAsyncioTestCase):
    async def test_disabled_scenarios_do_not_schedule_execution(self):
        runner = ScenarioRunner()

        try:
            for scenario_id in ("S02", "S03", "S04"):
                with self.subTest(scenario_id=scenario_id):
                    with self.assertRaises(ScenarioUnavailableError):
                        runner.start(scenario_id)

            self.assertIsNone(runner._active_task)
            self.assertEqual(runner._runs, {})
        finally:
            await runner.close()
