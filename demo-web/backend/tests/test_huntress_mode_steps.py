"""Huntress 모드별 실행 단계 선택과 공용 정의 유지 검사."""

import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, patch

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(BACKEND))

from app.services.runner import ScenarioRunner

from scenarios.catalog import get_scenario, to_public_dict


class HuntressModeStepTests(unittest.IsolatedAsyncioTestCase):
    async def check_mode(self, mode, expected_operations):
        original = get_scenario("S03")

        # 실제 catalog를 바꾸지 않고 검사할 모드만 허용한다.
        scenario = replace(
            original,
            modes=tuple(
                replace(
                    item,
                    enabled=True,
                    disabled_reason=None,
                )
                if item.id == mode
                else item
                for item in original.modes
            ),
        )

        runner = ScenarioRunner()

        try:
            with (
                patch(
                    "app.services.runner.get_scenario",
                    return_value=scenario,
                ),
                patch.object(
                    runner,
                    "_execute",
                    new=AsyncMock(),
                ) as execute,
            ):
                created = runner.start("S03", mode=mode)
                await runner._active_task

                record, selected_scenario = execute.await_args.args

                self.assertEqual(record.mode, mode)
                self.assertEqual(created.mode, mode)

                self.assertEqual(
                    [
                        name
                        for step in selected_scenario.steps
                        for name in step.operation_names
                    ],
                    expected_operations,
                )

                self.assertEqual(
                    [step.id for step in record.steps],
                    [step.id for step in selected_scenario.steps],
                )

            # 실행별 단계 선택이 공용 시나리오를 변경하면 안 된다.
            self.assertEqual(
                get_scenario("S03").steps,
                original.steps,
            )
        finally:
            await runner.close()

    async def test_read_keeps_existing_steps(self):
        await self.check_mode(
            "read",
            [
                "PRECHECK",
                "PREPARE",
                "VERIFY_READY",
                "READ",
                "VERIFY_MOUNT",
                "VERIFY_UNDERLAY",
            ],
        )

    async def test_honeypot_uses_observation_steps(self):
        await self.check_mode(
            "honeypot",
            [
                "PRECHECK",
                "HONEYPOT_READY",
                "HONEYPOT_ACCESS",
            ],
        )

    async def test_public_mode_steps_exclude_internal_operation_names(self):
        scenario = get_scenario("S03")
        public = to_public_dict(scenario)

        mode = next(item for item in public["modes"] if item["id"] == "honeypot")

        self.assertFalse(mode["enabled"])
        self.assertEqual(
            [step["id"] for step in mode["steps"]],
            [
                "precheck",
                "honeypot_ready",
                "honeypot_access",
            ],
        )
        self.assertTrue(all(set(step) == {"id", "name"} for step in mode["steps"]))


if __name__ == "__main__":
    unittest.main()
