#!/usr/bin/env python3
"""GuardFS HoneypotDetector 전용 경로·연산 단위 테스트

이 테스트는 FUSE를 마운트하지 않고 ``HoneypotDetector.check``의 입력과 판정만 검증
모든 테스트는 임시 루트 아래에 다음처럼 별도 경로를
만들어 일반 파일과 honeypot 파일을 혼동하지 않도록 한다.

    <temporary-root>/normal/
    <temporary-root>/honeypot/

검증:
    - honeypot 디렉터리와 내부 파일의 경계 판정
    - 지원되는 파일 연산(open/read/write/lookup/rename/unlink)
    - rename 출발지와 목적지 검사
    - ``..`` 및 symbolic link를 포함한 realpath 정규화
    - honeypot과 이름만 비슷한 sibling 경로의 오탐 방지
    - 현재 구현에서 탐지 대상으로 지정하지 않은 연산의 동작

주의:
    이 파일만으로는 실제 ``cat`` 출력 차단 여부를 검증할 수 없음
    실제 FUSE의 ``open/read`` 차단은 별도의 mount 통합 테스트에서 확인 필요

실행:
    python3 scripts/stage1/test_honeypot_rules.py -v
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from guardfs.stage1.honeypot import HoneypotDetector  # noqa: E402


@dataclass
class FakeEvent:
    """실제 FsEvent에서 HoneypotDetector가 읽는 필드만 표현한다."""

    op: str
    path: str
    new_path: str | None = None
    pid: int = 4242
    size: int = 0
    entropy: float | None = None


class HoneypotRuleTests(unittest.TestCase):
    """허니팟 경로와 정상 경로가 확실히 분리되는지 검사한다."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(prefix="guardfs-honeypot-")
        self.root = Path(self.tempdir.name)

        # 정상 파일 영역과 허니팟 영역을 의도적으로 분리한다.
        self.normal_dir = self.root / "normal"
        self.honeypot_dir = self.root / "honeypot"
        self.normal_dir.mkdir()
        self.honeypot_dir.mkdir()

        self.normal_file = self.normal_dir / "report.txt"
        self.honeypot_file = self.honeypot_dir / "system-update.txt"
        self.normal_file.write_text("normal test data", encoding="utf-8")
        self.honeypot_file.write_text("decoy test data", encoding="utf-8")

        # honeypot_backup은 honeypot의 자식이 아닌 sibling이다.
        self.honeypot_sibling = self.root / "honeypot_backup"
        self.honeypot_sibling.mkdir()
        (self.honeypot_sibling / "ordinary.txt").write_text(
            "ordinary data",
            encoding="utf-8",
        )

        self.detector = HoneypotDetector(str(self.honeypot_dir))

    def tearDown(self):
        self.tempdir.cleanup()

    def check(self, op: str, path: Path, new_path: Path | None = None) -> bool:
        """테스트 이벤트 생성을 한 곳에서 관리한다."""
        return self.detector.check(
            FakeEvent(
                op=op,
                path=str(path),
                new_path=str(new_path) if new_path is not None else None,
            )
        )

    def test_detector_stores_normalized_honeypot_directory(self):
        self.assertEqual(
            self.detector._honeypot_dir,
            os.path.realpath(self.honeypot_dir),
        )

    def test_exact_honeypot_directory_is_detected_for_lookup(self):
        self.assertTrue(self.check("lookup", self.honeypot_dir))

    def test_file_inside_honeypot_is_detected_for_all_supported_operations(self):
        supported_operations = ("open", "read", "write", "lookup", "rename", "unlink")

        for op in supported_operations:
            with self.subTest(op=op):
                self.assertTrue(self.check(op, self.honeypot_file))

    def test_normal_file_is_not_detected_for_supported_operations(self):
        supported_operations = ("open", "read", "write", "lookup", "rename", "unlink")

        for op in supported_operations:
            with self.subTest(op=op):
                self.assertFalse(self.check(op, self.normal_file))

    def test_honeypot_sibling_prefix_is_not_detected(self):
        sibling_file = self.honeypot_sibling / "ordinary.txt"
        self.assertFalse(self.check("read", sibling_file))
        self.assertFalse(self.check("write", sibling_file))

    def test_parent_traversal_into_honeypot_is_detected(self):
        disguised_path = self.normal_dir / ".." / "honeypot" / "system-update.txt"
        self.assertTrue(self.check("read", disguised_path))

    def test_parent_traversal_out_of_honeypot_is_not_detected(self):
        escaped_path = self.honeypot_dir / ".." / "normal" / "report.txt"
        self.assertFalse(self.check("read", escaped_path))

    def test_rename_from_normal_to_honeypot_is_detected(self):
        self.assertTrue(
            self.check(
                "rename",
                self.normal_file,
                self.honeypot_dir / "incoming.txt",
            )
        )

    def test_rename_from_honeypot_to_normal_is_detected(self):
        self.assertTrue(
            self.check(
                "rename",
                self.honeypot_file,
                self.normal_dir / "moved-out.txt",
            )
        )

    def test_rename_between_normal_paths_is_not_detected(self):
        self.assertFalse(
            self.check(
                "rename",
                self.normal_file,
                self.normal_dir / "renamed.txt",
            )
        )

    def test_missing_new_path_does_not_break_non_rename_event(self):
        self.assertFalse(self.check("read", self.normal_file))
        self.assertTrue(self.check("read", self.honeypot_file))

    def test_missing_new_path_for_rename_is_not_detected(self):
        self.assertFalse(self.check("rename", self.normal_file))

    def test_currently_unsupported_operations_are_not_reported(self):
        # 이 결과는 보안적으로 충분하다는 뜻이 아니라, 현재 구현의
        # 지원 연산 목록을 고정해 두기 위한 기준선이다.
        unsupported_operations = ("create", "mkdir", "rmdir", "truncate", "ftruncate")

        for op in unsupported_operations:
            with self.subTest(op=op):
                self.assertFalse(self.check(op, self.honeypot_file))

    def test_symlink_resolving_into_honeypot_is_detected(self):
        link = self.normal_dir / "decoy-link.txt"
        try:
            link.symlink_to(self.honeypot_file)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symbolic link creation unavailable: {exc}")

        self.assertTrue(self.check("read", link))

    def test_symlink_inside_honeypot_resolving_outside_is_not_detected(self):
        outside = self.normal_dir / "outside.txt"
        link = self.honeypot_dir / "external-link.txt"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symbolic link creation unavailable: {exc}")

        self.assertFalse(self.check("read", link))


def main() -> int:
    parser = argparse.ArgumentParser(description="GuardFS HoneypotDetector 테스트")
    parser.add_argument(
        "tests",
        nargs="*",
        help="선택 실행할 TestCase 클래스명 또는 test id",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    loader = unittest.defaultTestLoader
    if not args.tests:
        suite = loader.loadTestsFromModule(sys.modules[__name__])
    else:
        test_names = []
        for name in args.tests:
            if not name.startswith(f"{__name__}."):
                name = f"{__name__}.{name}"
            test_names.append(name)
        suite = loader.loadTestsFromNames(test_names)

    runner = unittest.TextTestRunner(verbosity=2 if args.verbose else 1)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
