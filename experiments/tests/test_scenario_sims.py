#!/usr/bin/env python3
"""
시나리오 시뮬레이터의 FUSE-비의존 로직을 검증한다 (GuardFS 실행/마운트 불필요).

테스트 방법:
  cd ~/Capstone
  source venv/bin/activate   # (여기서는 표준 라이브러리만 쓰므로 venv 없이도 동작)
  python experiments/tests/test_scenario_sims.py

검사 범위(실제 FUSE 탐지/차단은 검증하지 않는다):
  - scenario_lib: 광범위 대상 거부, 전용 workdir 생성, 평문 준비/공개 확인(PID 분리),
    난수/부분 덮어쓰기(head/tail·비율), 평문 보존 영역, 정리, 인자 검증 헬퍼
  - 각 시뮬레이터: argparse 경계값 거부, 대상 폴더 거부 시 공격 미시작
  임시 디렉터리와 mock 을 사용한다.
"""

from __future__ import annotations

import importlib.util
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SIM_DIR = Path(__file__).resolve().parents[1] / "simulators"
sys.path.insert(0, str(SIM_DIR))

import scenario_lib as lib  # noqa: E402


def _load(name: str):
    source = SIM_DIR / name
    spec = importlib.util.spec_from_file_location(name[:-3], source)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


icefire = _load("sim_scn_icefire.py")
darkradiation = _load("sim_scn_darkradiation.py")
huntress = _load("sim_scn_huntress.py")
akira = _load("sim_scn_akira.py")


# --------------------------------------------------------------------------- #
# scenario_lib 안전 불변식
# --------------------------------------------------------------------------- #

class ScenarioLibTargetTests(unittest.TestCase):
    def test_root_is_rejected(self):
        with patch.object(lib.sys, "stderr", io.StringIO()):
            self.assertIsNone(lib.resolve_target("/"))

    def test_home_is_rejected(self):
        with patch.object(lib.sys, "stderr", io.StringIO()):
            self.assertIsNone(lib.resolve_target("~"))

    def test_subfolder_is_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            sub = os.path.join(tmp, "sim_target")
            self.assertEqual(lib.resolve_target(sub), os.path.realpath(sub))

    def test_make_workdir_creates_fresh_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            wd = lib.make_workdir(tmp, "icefire")
            self.assertTrue(os.path.isdir(wd))
            self.assertIn("icefire", os.path.basename(wd))
            # 같은 초에 다시 만들면 exist_ok=False 로 실패해야 한다(폴더 재사용 금지).
            with patch.object(lib.time, "strftime", return_value=os.path.basename(wd)):
                with self.assertRaises(FileExistsError):
                    lib.make_workdir(tmp, "icefire")


class ScenarioLibPrepareTests(unittest.TestCase):
    def test_prepare_and_verify_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            names = ["a.txt", "sub/b.txt"]
            size = 300
            self.assertTrue(lib.prepare_plaintext_files(tmp, names, size, 10))
            self.assertTrue(lib._files_ready(tmp, names, size))
            # 크기가 다르면 준비되지 않은 것으로 본다.
            self.assertFalse(lib._files_ready(tmp, names, size + 1))

    def test_missing_file_not_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(lib._files_ready(tmp, ["x.txt"], 128))

    def test_wait_for_child_reaps_timed_out_child(self):
        fake_os = SimpleNamespace(WNOHANG=1)
        with (
            patch.object(fake_os, "waitpid", side_effect=[(0, 0), (7, 0)], create=True) as waitpid,
            patch.object(fake_os, "kill", create=True) as kill,
            patch.object(lib, "os", fake_os),
            patch.object(lib, "signal", SimpleNamespace(SIGKILL=9)),
            patch.object(lib.time, "monotonic", side_effect=[0, 2]),
            patch.object(lib.sys, "stderr", io.StringIO()),
        ):
            self.assertFalse(lib.wait_for_child(7, 1, "test"))
            kill.assert_called_once_with(7, 9)
            self.assertEqual(waitpid.call_args.args, (7, 0))


class ScenarioLibOverwriteTests(unittest.TestCase):
    def test_overwrite_random_fills_whole_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "f")
            Path(p).write_bytes(b"\x00" * 1000)
            n = lib.overwrite_random(p, 1000, 256)
            self.assertEqual(n, 1000)
            self.assertEqual(os.path.getsize(p), 1000)

    def test_overwrite_partial_leaves_plaintext_tail(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "f")
            plain = b"P" * 1000
            Path(p).write_bytes(plain)
            n = lib.overwrite_partial(p, 1000, 20, 256)  # 앞 20%
            self.assertEqual(n, 200)
            data = Path(p).read_bytes()
            self.assertEqual(data[200:], plain[200:])  # 뒷부분 평문 보존

    def test_write_note_and_read_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            note = lib.write_note(tmp, "note.txt", "hello")
            self.assertEqual(lib.read_file(note), 5)


class ScenarioLibValidatorTests(unittest.TestCase):
    def test_validate_positive_rejects_zero_and_nan(self):
        errs = []
        parser = SimpleNamespace(error=lambda m: errs.append(m))
        lib.validate_positive(parser, duration=0)
        lib.validate_positive(parser, timeout=float("nan"))
        lib.validate_positive(parser, ok=1.0)  # 통과
        self.assertEqual(len(errs), 2)


# --------------------------------------------------------------------------- #
# Akira: head/tail 부분 덮어쓰기 위치
# --------------------------------------------------------------------------- #

class AkiraPartialTests(unittest.TestCase):
    def test_tail_overwrite_preserves_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "vm.vmdk")
            plain = b"H" * 1000
            Path(p).write_bytes(plain)
            akira.overwrite_partial_at(p, 1000, 20, 256, "tail")
            data = Path(p).read_bytes()
            self.assertEqual(data[:800], plain[:800])  # 헤더(앞 80%) 보존

    def test_head_overwrite_changes_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "vm.vmdk")
            plain = b"H" * 1000
            Path(p).write_bytes(plain)
            akira.overwrite_partial_at(p, 1000, 20, 256, "head")
            data = Path(p).read_bytes()
            self.assertNotEqual(data[:200], plain[:200])  # 앞부분 변경


# --------------------------------------------------------------------------- #
# argparse 경계값 / 대상 거부
# --------------------------------------------------------------------------- #

class ArgparseBoundaryTests(unittest.TestCase):
    def _expect_exit(self, mod, argv):
        with (
            patch.object(mod.sys, "argv", argv),
            patch.object(sys, "stderr", io.StringIO()),
        ):
            with self.assertRaises(SystemExit) as e:
                mod.parse_args()
            self.assertEqual(e.exception.code, 2)

    def test_icefire_rejects_bad_values(self):
        self._expect_exit(icefire, ["x", "t", "--files", "0"])
        self._expect_exit(icefire, ["x", "t", "--duration", "0"])

    def test_akira_rejects_percent_out_of_range(self):
        self._expect_exit(akira, ["x", "t", "--encryption-percent", "0"])
        self._expect_exit(akira, ["x", "t", "--encryption-percent", "150"])

    def test_darkradiation_rejects_bad_files(self):
        self._expect_exit(darkradiation, ["x", "t", "--files", "-1"])

    def test_huntress_rejects_bad_values(self):
        self._expect_exit(huntress, ["x", "t", "--log-files", "0"])


class UnsafeTargetStopsAttackTests(unittest.TestCase):
    """대상 폴더가 거부되면 각 시뮬레이터는 공격을 시작하지 않고 2를 반환한다."""

    def _run_with_target(self, mod, argv):
        with (
            patch.object(mod.sys, "argv", argv),
            patch.object(sys, "stdout", io.StringIO()),
            patch.object(sys, "stderr", io.StringIO()),
            patch.object(mod.lib, "make_workdir") as make_wd,
            patch.object(mod.lib, "prepare_plaintext_files") as prep,
        ):
            rc = mod.main()
            return rc, make_wd, prep

    def test_icefire_root_target(self):
        rc, make_wd, prep = self._run_with_target(icefire, ["x", "/"])
        self.assertEqual(rc, 2)
        make_wd.assert_not_called()
        prep.assert_not_called()

    def test_akira_root_target(self):
        rc, make_wd, prep = self._run_with_target(akira, ["x", "/"])
        self.assertEqual(rc, 2)
        make_wd.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
