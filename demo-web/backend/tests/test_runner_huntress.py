"""Huntress 일반 읽기의 runner 연결과 최종 결과 검증."""

import asyncio
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(BACKEND))

from app.schemas.run import RunEventCollection, RunProcess
from app.services.runner import ScenarioRunner, now

from scenarios.catalog import get_scenario
from scenarios.huntress_config import READ_FILES

작업목록 = (
    ("huntress_prepare", "prepare", "PREPARE"),
    ("huntress_verify_ready", "verify", "VERIFY_READY"),
    ("huntress_read", "read", "READ"),
    ("huntress_verify_mount", "verify", "VERIFY_MOUNT"),
    ("huntress_verify_underlay", "verify", "VERIFY_UNDERLAY"),
)


class HuntressRunnerTests(unittest.IsolatedAsyncioTestCase):
    def 결과생성(self, 상태="passed"):
        """관리자가 반환하는 형식의 최종 결과를 만든다."""
        실패정보 = {
            "operation": "read",
            "path": "/runtime/mount/test/.ssh/id_rsa",
            "errno": 13 if 상태 == "failed" else None,
            "message": (
                "읽기 제한 시간을 초과했습니다."
                if 상태 == "timed_out"
                else "테스트용 읽기 접근 거절"
            ),
        }

        단계결과 = [
            {
                "name": "PRECHECK",
                "status": "passed",
                "planned": 1,
                "attempted": 1,
                "completed": 1,
                "failure": None,
            }
        ]
        자식결과 = []

        for 순서, (역할, 작업, 단계명) in enumerate(작업목록):
            실패 = 단계명 == "READ" and 상태 != "passed"

            단계 = {
                "name": 단계명,
                "status": "failed" if 실패 else "passed",
                "planned": 1,
                "attempted": 1,
                "completed": 0 if 실패 else 1,
                "failure": 실패정보.copy() if 실패 else None,
            }
            if 실패:
                단계["error"] = 실패정보["message"]

            단계결과.append(단계)

            파일결과 = []
            for 번호, 파일명 in enumerate(READ_FILES):
                파일실패 = 실패 and 번호 == 0

                항목 = {
                    "name": 파일명,
                    "path": f"/runtime/mount/test/{파일명}",
                    "status": "failed" if 파일실패 else "passed",
                }

                if 작업 in ("read", "verify"):
                    항목["content_matched"] = True

                파일결과.append(항목)

            자식결과.append(
                {
                    "role": 역할,
                    "pid": 200 + 순서,
                    "action": 작업,
                    "status": 상태 if 실패 else "passed",
                    "planned": 6,
                    "attempted": 6,
                    "completed": 5 if 실패 else 6,
                    "failure": 실패정보.copy() if 실패 else None,
                    "operations": 파일결과,
                }
            )

            # 실패한 읽기 뒤의 내용 검증은 실행하지 않는다.
            if 실패:
                break

        return {
            "result_version": 2,
            "scenario_id": "S03",
            "mode": "read",
            "pid": 123,
            "holdfs_pid": 999,
            "status": 상태,
            "termination_reason": {
                "passed": "completed",
                "failed": "operation_failed",
                "timed_out": "deadline_exceeded",
            }[상태],
            "steps": 단계결과,
            "task_results": 자식결과,
            "content_verification": (
                {
                    "status": "passed",
                    "files": 6,
                    "observed_at": now().isoformat(),
                }
                if 상태 == "passed"
                else {"status": "not_checked"}
            ),
            "detection_verification": "not_checked",
        }

    async def 실행검사(
        self,
        결과,
        *,
        잘못된결과=False,
        등록누락역할=None,
    ):
        """실제 runner를 실행하고 외부 프로세스만 대체한다."""
        시나리오 = get_scenario("S03")
        self.assertIsNotNone(시나리오)
        self.assertTrue(시나리오.enabled)
        self.assertEqual(
            시나리오.module,
            "scenarios.s03_huntress",
        )

        실행관리자 = ScenarioRunner()
        가짜프로세스 = SimpleNamespace(
            pid=123,
            returncode=0 if 결과["status"] == "passed" else 1,
        )

        처리순서 = []
        적용제한시간 = []
        원래대기함수 = asyncio.wait

        async def 결과수집(프로세스, 기록, 정의):
            # 실제 실행에서는 등록 이벤트를 받아 채워지는 정보다.
            for 순서, (역할, _, _) in enumerate(작업목록):
                if 역할 == 등록누락역할:
                    continue

                기록.processes.append(
                    RunProcess(
                        role=역할,
                        pid=200 + 순서,
                        start_time_ticks=1000 + 순서,
                        registered_at=now(),
                    )
                )

            return json.dumps(결과).encode("utf-8")

        async def 프로세스정리(*인자):
            처리순서.append("프로세스 정리")

        def 이벤트수집(*인자):
            처리순서.append("이벤트 수집")
            return RunEventCollection(issues=[])

        async def 제한시간확인(대상, **옵션):
            적용제한시간.append(옵션.get("timeout"))
            return await 원래대기함수(대상, **옵션)

        try:
            with (
                patch.object(
                    실행관리자,
                    "_capture_event_logs",
                    return_value=([], []),
                ),
                patch(
                    "app.services.runner.asyncio.create_subprocess_exec",
                    new=AsyncMock(return_value=가짜프로세스),
                ) as 프로세스생성,
                patch.object(
                    실행관리자,
                    "_collect_output",
                    new=AsyncMock(side_effect=결과수집),
                ),
                patch.object(
                    실행관리자,
                    "_terminate_process_group",
                    new=AsyncMock(side_effect=프로세스정리),
                ) as 정리호출,
                patch.object(
                    실행관리자,
                    "_collect_run_events",
                    side_effect=이벤트수집,
                ) as 이벤트호출,
                patch(
                    "app.services.runner.asyncio.wait",
                    side_effect=제한시간확인,
                ),
            ):
                if 잘못된결과:
                    with self.assertLogs(
                        "app.services.runner",
                        level="ERROR",
                    ):
                        생성응답 = 실행관리자.start(
                            "S03",
                            mode="read",
                        )
                        await asyncio.wait_for(
                            실행관리자._active_task,
                            timeout=5,
                        )
                else:
                    생성응답 = 실행관리자.start(
                        "S03",
                        mode="read",
                    )
                    await asyncio.wait_for(
                        실행관리자._active_task,
                        timeout=5,
                    )

                기록 = 실행관리자.get(생성응답.run_id)
                명령 = 프로세스생성.call_args.args

                self.assertEqual(생성응답.mode, "read")
                self.assertEqual(기록.mode, "read")

                self.assertEqual(
                    명령[명령.index("-m") + 1],
                    "scenarios.s03_huntress",
                )
                self.assertEqual(명령.count("--mode"), 1)
                self.assertEqual(
                    명령[명령.index("--mode") + 1],
                    "read",
                )
                self.assertEqual(
                    명령[명령.index("--work-dir-name") + 1],
                    기록.workspace.name,
                )
                self.assertEqual(
                    기록.workspace.name,
                    f"s03_{생성응답.run_id}",
                )
                self.assertEqual(
                    float(명령[명령.index("--total-timeout") + 1]),
                    120.0,
                )
                self.assertEqual(적용제한시간, [120.0])

                정리호출.assert_awaited_once_with(가짜프로세스)
                이벤트호출.assert_called_once()

            self.assertEqual(
                처리순서,
                ["프로세스 정리", "이벤트 수집"],
            )
            self.assertIsNotNone(기록.finished_at)
            self.assertEqual(
                기록.detection_verification,
                "not_checked",
            )

            return 기록
        finally:
            await 실행관리자.close()

    async def test_일반읽기_전체완료(self):
        결과 = self.결과생성()
        기록 = await self.실행검사(결과)

        self.assertEqual(기록.status, "passed")
        self.assertEqual(기록.result, 결과)
        self.assertTrue(all(단계.status == "passed" for 단계 in 기록.steps))

        # 읽기 완료를 공격 차단 성공으로 판정하지 않는다.
        self.assertIsNone(기록.protection_verification)
        self.assertEqual(
            기록.result["content_verification"]["status"],
            "passed",
        )

    async def test_읽기실패와_시간초과의_부분결과보존(self):
        for 상태 in ("failed", "timed_out"):
            with self.subTest(상태=상태):
                결과 = self.결과생성(상태)
                기록 = await self.실행검사(결과)

                self.assertEqual(기록.status, 상태)
                self.assertEqual(기록.result, 결과)
                self.assertEqual(
                    기록.result["task_results"][-1]["completed"],
                    5,
                )
                self.assertEqual(
                    기록.steps[-1].status,
                    "skipped",
                )

    async def test_모드가다른_결과거절(self):
        결과 = self.결과생성()
        결과["mode"] = "honeypot"

        기록 = await self.실행검사(
            결과,
            잘못된결과=True,
        )

        self.assertEqual(기록.status, "failed")
        self.assertIsNone(기록.result)
        self.assertIn("실행 모드", 기록.error)

    async def test_등록되지않은_자식결과거절(self):
        결과 = self.결과생성()

        기록 = await self.실행검사(
            결과,
            잘못된결과=True,
            등록누락역할="huntress_read",
        )

        self.assertEqual(기록.status, "failed")
        self.assertIsNone(기록.result)
        self.assertIn("등록되지 않은", 기록.error)

    async def test_내용검증이누락된_성공결과거절(self):
        결과 = self.결과생성()
        결과["content_verification"] = {
            "status": "not_checked",
        }

        기록 = await self.실행검사(
            결과,
            잘못된결과=True,
        )

        self.assertEqual(기록.status, "failed")
        self.assertIsNone(기록.result)
        self.assertIn("내용 불변", 기록.error)

    async def test_완료수가부족한_성공결과거절(self):
        결과 = self.결과생성()
        결과["task_results"][2]["completed"] = 5

        기록 = await self.실행검사(
            결과,
            잘못된결과=True,
        )

        self.assertEqual(기록.status, "failed")
        self.assertIsNone(기록.result)


if __name__ == "__main__":
    unittest.main()
