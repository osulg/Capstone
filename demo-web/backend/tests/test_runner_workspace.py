"""실행별 작업 경로 기록과 S01 실행 인자 전달을 확인한다."""

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(BACKEND))

HAS_PYDANTIC = importlib.util.find_spec("pydantic") is not None
if HAS_PYDANTIC:
    from app.services.runner import ScenarioRunner


@unittest.skipUnless(HAS_PYDANTIC, "백엔드 Pydantic 환경이 필요합니다.")
class RunnerWorkspaceTests(unittest.IsolatedAsyncioTestCase):
    async def test_workspace_survives_cancel_before_spawn(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = ScenarioRunner(
                mount_path=root / "mount",
                underlay_path=root / "underlay",
            )
            try:
                names = []
                for _ in range(2):
                    created = runner.start("S01")
                    runner.cancel(created.run_id)
                    await runner._active_task

                    result = runner.get(created.run_id)
                    self.assertEqual(result.status, "cancelled")
                    self.assertIsNone(result.result)
                    self.assertIsNotNone(result.workspace)
                    workspace = result.workspace
                    self.assertEqual(workspace.name, f"s01_{created.run_id}")
                    self.assertEqual(
                        Path(workspace.mount_path),
                        runner.mount_path / workspace.name,
                    )
                    self.assertEqual(
                        Path(workspace.underlay_path),
                        runner.underlay_path / workspace.name,
                    )
                    # 경로 기록만으로 폴더를 생성하지 않는다.
                    self.assertFalse(Path(workspace.mount_path).exists())
                    names.append(workspace.name)
                self.assertNotEqual(names[0], names[1])
            finally:
                await runner.close()

    async def test_s01_receives_recorded_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = ScenarioRunner(
                mount_path=root / "mount",
                underlay_path=root / "underlay",
            )
            try:
                # 실제 프로세스를 만들기 직전의 인자를 검사한다.
                with patch(
                    "app.services.runner.asyncio.create_subprocess_exec",
                    new=AsyncMock(side_effect=OSError("test spawn stopped")),
                ) as spawn, self.assertLogs("app.services.runner", level="ERROR"):
                    created = runner.start("S01")
                    await runner._active_task

                record = runner.get(created.run_id)
                arguments = spawn.call_args.args
                self.assertIn("--wait-registration-ack", arguments)
                self.assertEqual(
                    arguments[arguments.index("--work-dir-name") + 1],
                    record.workspace.name,
                )
                self.assertEqual(
                    arguments[arguments.index("--mount") + 1],
                    str(runner.mount_path),
                )
                self.assertEqual(
                    arguments[arguments.index("--underlay") + 1],
                    str(runner.underlay_path),
                )
            finally:
                await runner.close()


if __name__ == "__main__":
    unittest.main()
