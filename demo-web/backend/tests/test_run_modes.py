"""S03 모드 요청 검증과 실행 응답의 모드 보존 검사."""

import sys
import unittest
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(BACKEND.parents[1]))

from dataclasses import replace
from unittest.mock import patch

from app.schemas.run import (
    RunCreatedResponse,
    RunRequest,
    RunResponse,
)
from app.services.runner import ScenarioRunner, ScenarioUnavailableError, now
from pydantic import ValidationError

from scenarios.catalog import get_scenario


class RunModeTests(unittest.TestCase):
    def test_s03_accepts_three_modes(self):
        for mode in ("read", "honeypot", "delete"):
            with self.subTest(mode=mode):
                request = RunRequest(
                    scenario_id="S03",
                    mode=mode,
                )
                self.assertEqual(request.mode, mode)

    def test_s03_requires_mode(self):
        with self.assertRaises(ValidationError):
            RunRequest(scenario_id="S03")

    def test_unknown_mode_is_rejected(self):
        with self.assertRaises(ValidationError):
            RunRequest(scenario_id="S03", mode="unknown")

    def test_other_scenarios_reject_mode(self):
        for scenario_id in ("S01", "S02", "S04"):
            with self.subTest(scenario_id=scenario_id):
                with self.assertRaises(ValidationError):
                    RunRequest(
                        scenario_id=scenario_id,
                        mode="read",
                    )

    def test_s01_without_mode_remains_valid(self):
        request = RunRequest(scenario_id="S01")
        self.assertIsNone(request.mode)

    def test_mode_survives_response_serialization(self):
        created = RunCreatedResponse(
            run_id="test-run",
            scenario_id="S03",
            mode="honeypot",
            status="queued",
        )
        record = RunResponse(
            run_id=created.run_id,
            scenario_id=created.scenario_id,
            mode=created.mode,
            status="queued",
            created_at=now(),
        )

        restored = RunResponse.model_validate_json(record.model_dump_json())

        self.assertEqual(restored.mode, "honeypot")
        self.assertEqual(created.model_dump()["mode"], "honeypot")


class HuntressModeAvailabilityTests(unittest.IsolatedAsyncioTestCase):
    async def test_disabled_mode_is_rejected(self):
        original = get_scenario("S03")
        reason = "테스트에서 비활성화한 모드입니다."

        # 실제 카탈로그는 유지하고 테스트에서만 삭제 모드를 비활성화한다.
        scenario = replace(
            original,
            modes=tuple(
                replace(
                    mode,
                    enabled=False,
                    disabled_reason=reason,
                )
                if mode.id == "delete"
                else mode
                for mode in original.modes
            ),
        )
        runner = ScenarioRunner()

        try:
            with patch(
                "app.services.runner.get_scenario",
                return_value=scenario,
            ):
                with self.assertRaises(ScenarioUnavailableError) as caught:
                    runner.start("S03", mode="delete")

                self.assertEqual(str(caught.exception), reason)

            self.assertIsNone(runner._active_task)
            self.assertEqual(runner._runs, {})
        finally:
            await runner.close()


if __name__ == "__main__":
    unittest.main()
