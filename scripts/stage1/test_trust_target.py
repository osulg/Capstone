"""
신뢰 판정의 인터프리터 대상 해석 테스트 (FUSE 없이 실행)

    python3 -m pytest scripts/stage1/test_trust_target.py

is_trusted_pid(첫 쓰기 전 선제 MEDIUM)와 passthrough.is_trusted_process(SUSPICIOUS 처리)가
같은 기준으로 인터프리터의 실제 실행 대상(스크립트·모듈·인라인 코드)을 보는지 확인한다.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import trio  # noqa: E402

from guardfs.stage1 import trust  # noqa: E402
from guardfs.stage1.trust import classify_interpreter_args as classify  # noqa: E402


class ClassifyInterpreterArgsTests(unittest.TestCase):
    def test_non_interpreter_keeps_exe(self):
        self.assertEqual(classify("/usr/bin/openssl", ["enc"], "/tmp"), ("not_interpreter", "/usr/bin/openssl"))

    def test_python_script_absolute_and_relative(self):
        self.assertEqual(classify("/usr/bin/python3.12", ["-u", "/usr/local/bin/holdfs_sim.py", "x"], "/home/u"),
                         ("script", "/usr/local/bin/holdfs_sim.py"))
        kind, path = classify("/usr/bin/python3.12", ["tool.py"], "/home/u/proj")
        self.assertEqual((kind, path), ("script", "/home/u/proj/tool.py"))  # 대상 프로세스의 cwd 기준

    def test_python_module_resolved_from_cwd(self):
        with tempfile.TemporaryDirectory() as cwd:
            pkg = Path(cwd) / "scenarios"
            pkg.mkdir()
            (pkg / "akira_tasks.py").write_text("")
            kind, path = classify("/usr/bin/python3.12", ["-u", "-m", "scenarios.akira_tasks", "--x"], cwd)
            self.assertEqual(kind, "script")
            self.assertEqual(path, os.path.realpath(pkg / "akira_tasks.py"))
            # cwd 에 없는 모듈은 확인할 수 없다
            self.assertEqual(classify("/usr/bin/python3", ["-m", "json.tool"], cwd), ("unknown", ""))

    def test_inline_code_and_stdin(self):
        self.assertEqual(classify("/usr/bin/python3", ["-c", "print(1)"], "/"), ("inline", ""))
        self.assertEqual(classify("/usr/bin/bash", ["-c", "echo x > f"], "/"), ("inline", ""))
        self.assertEqual(classify("/usr/bin/perl", ["-e", "1"], "/"), ("inline", ""))
        self.assertEqual(classify("/usr/bin/python3", ["-"], "/"), ("stdin", ""))
        self.assertEqual(classify("/usr/bin/bash", [], "/"), ("stdin", ""))        # 대화형 셸
        self.assertEqual(classify("/usr/bin/bash", ["--login"], "/"), ("stdin", ""))
        self.assertEqual(classify("/usr/bin/python3", ["-u"], "/"), ("stdin", ""))  # REPL

    def test_option_values_are_not_targets(self):
        self.assertEqual(classify("/usr/bin/python3", ["-W", "ignore", "/usr/bin/x.py"], "/"),
                         ("script", "/usr/bin/x.py"))
        self.assertEqual(classify("/usr/bin/bash", ["-o", "pipefail", "/home/u/run.sh"], "/"),
                         ("script", "/home/u/run.sh"))
        self.assertEqual(classify("/usr/bin/php", ["-f", "/usr/share/x.php"], "/"), ("script", "/usr/share/x.php"))

    def test_trusted_script_path(self):
        self.assertTrue(trust.is_trusted_script_path("/usr/local/bin/holdfs_sim.py"))
        self.assertTrue(trust.is_trusted_script_path("/usr/bin/x.py"))
        self.assertFalse(trust.is_trusted_script_path("/usr/binx/x.py"))
        self.assertFalse(trust.is_trusted_script_path("/home/u/Capstone/scenarios/akira_tasks.py"))
        self.assertFalse(trust.is_trusted_script_path("/tmp/x.py"))
        self.assertFalse(trust.is_trusted_script_path(""))


class IsTrustedPidTests(unittest.TestCase):
    """패키지 검증을 통과한 인터프리터라도 실행 대상에 따라 판정이 갈리는지 확인한다."""

    def run_case(self, target, exe="/usr/bin/python3.12"):
        trust._trust_cache.clear()

        async def verified(_exe):
            return True

        with (patch.object(trust, "_get_start_time", return_value=None),
              patch.object(trust, "_get_exe_path", return_value=exe),
              patch.object(trust, "_get_parent_pid", return_value=None),
              patch.object(trust, "is_package_verified", verified),
              patch.object(trust, "interpreter_target", return_value=target)):
            return trio.run(trust.is_trusted_pid, 4242)

    def test_system_interpreter_with_home_module_is_untrusted(self):
        # S03: venv → /usr/bin/python3.12 -m scenarios.akira_tasks (홈 디렉터리)
        self.assertFalse(self.run_case(("script", "/home/u/Capstone/scenarios/akira_tasks.py")))

    def test_system_interpreter_with_trusted_script_is_trusted(self):
        # S04: /usr/bin/python3 /usr/local/bin/holdfs_sim.py
        self.assertTrue(self.run_case(("script", "/usr/local/bin/holdfs_sim.py")))

    def test_inline_and_unknown_are_untrusted(self):
        self.assertFalse(self.run_case(("inline", "")))
        self.assertFalse(self.run_case(("unknown", "")))

    def test_interactive_shell_and_binaries_keep_exe_rule(self):
        self.assertTrue(self.run_case(("stdin", ""), exe="/usr/bin/bash"))
        self.assertTrue(self.run_case(("not_interpreter", "/usr/bin/cp"), exe="/usr/bin/cp"))


class PassthroughTargetTests(unittest.TestCase):
    def test_passthrough_uses_same_target(self):
        try:
            from guardfs.fuse_fs import passthrough
        except ImportError as error:  # pyfuse3 가 없는 환경
            self.skipTest(f"passthrough import 불가: {error}")
        cases = {
            ("script", "/usr/local/bin/x.py"): "/usr/local/bin/x.py",
            ("inline", ""): "",
            ("stdin", ""): "",
            ("unknown", ""): "",
            ("not_interpreter", "/usr/bin/cp"): "/usr/bin/cp",
        }
        for target, expected in cases.items():
            with (patch.object(passthrough.os, "readlink", return_value="/usr/bin/python3.12"),
                  patch.object(passthrough, "interpreter_target", return_value=target)):
                self.assertEqual(passthrough._resolve_trust_target(1), expected)


if __name__ == "__main__":
    unittest.main()
