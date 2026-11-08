"""허니팟 미끼 사전 확인과 접근 결과 분리 검사."""

import errno
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scenarios.huntress_honeypot_tasks import execute_task


class HoneypotTaskTests(unittest.TestCase):
    def test_precheck_uses_underlay_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mount = root / "mount"
            underlay = root / "underlay"
            decoys = underlay / "honeypot"
            decoys.mkdir(parents=True)

            # 검사 대상과 독립적으로 기존 실험의 미끼 목록을 명시한다.
            names = (
                "id_rsa",
                "credentials",
                "config",
                ".env",
                "api_token.txt",
            )
            for name in names:
                (decoys / name).write_text(
                    "DUMMY DECOY\n",
                    encoding="utf-8",
                )

            result = execute_task("check", mount, underlay, 30.0)

            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["completed"], 5)
            self.assertEqual(
                [item["name"] for item in result["operations"]],
                list(names),
            )

            # 사전 확인 때문에 mount 경로가 생성되면 안 된다.
            self.assertFalse(mount.exists())

            # 기존 미끼 내용을 변경하지 않았는지 확인한다.
            for name in names:
                self.assertEqual(
                    (decoys / name).read_text(encoding="utf-8"),
                    "DUMMY DECOY\n",
                )

    def test_missing_decoys_fail_without_creating_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            underlay = root / "underlay"
            decoys = underlay / "honeypot"
            decoys.mkdir(parents=True)

            result = execute_task(
                "check",
                root / "mount",
                underlay,
                30.0,
            )

            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["completed"], 0)
            self.assertEqual(list(decoys.iterdir()), [])

    def test_permission_denied_is_not_reported_as_confirmed_block(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            with (
                patch(
                    "pathlib.Path.open",
                    side_effect=PermissionError(
                        errno.EACCES,
                        "테스트용 접근 거절",
                    ),
                ),
                patch("scenarios.huntress_honeypot_tasks.time.sleep"),
                patch("scenarios.huntress_honeypot_tasks.emit_access_event"),
            ):
                result = execute_task(
                    "access",
                    root / "mount",
                    root / "underlay",
                    30.0,
                )

            # 관찰 완료와 정책 차단 확정은 구분한다.
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["completed"], 5)
            self.assertTrue(
                all(
                    item["outcome"] == "permission_denied"
                    for item in result["operations"]
                )
            )

    def test_missing_files_are_distinguished_from_permission_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            with (
                patch("scenarios.huntress_honeypot_tasks.time.sleep"),
                patch("scenarios.huntress_honeypot_tasks.emit_access_event"),
            ):
                result = execute_task(
                    "access",
                    root / "mount",
                    root / "underlay",
                    30.0,
                )

            self.assertEqual(result["completed"], 5)
            self.assertTrue(
                all(item["outcome"] == "missing" for item in result["operations"])
            )


if __name__ == "__main__":
    unittest.main()
