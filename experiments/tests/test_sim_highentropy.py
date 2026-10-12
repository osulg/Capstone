"""시뮬레이터의 준비 완료 검사와 공격 시작 조건을 검증한다.

테스트 방법 (GuardFS 실행 및 FUSE mount 불필요):
  cd ~/Capstone
  source venv/bin/activate
  python experiments/tests/test_sim_highentropy.py

확인 기준:
  - 마지막에 'Ran 8 tests'와 'OK'가 나오면 통과한다.
  - 시간 초과 및 준비 확인 실패 메시지는 실패 상황을 의도적으로 검사한
    결과일 수 있다. 최종 unittest 결과로 성공/실패를 판단한다.

검사 범위:
  파일 누락, 평문 내용/크기 확인, 접근 오류, 자식 종료 상태, 시간 초과 시
  자식 정리, 준비 실패 시 공격 미시작과 폴더 보존, 잘못된 인자 거부.
  임시 파일과 mock을 사용하며 실제 FUSE 탐지/차단은 검증하지 않는다.
"""

import importlib.util
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "simulators" / "sim_highentropy.py"
spec = importlib.util.spec_from_file_location("sim_highentropy", SOURCE)
sim = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sim)


class PreparationTests(unittest.TestCase):
    def test_missing_file_is_not_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(sim._prepared_files_ready(tmp, 1, 128))

    def test_all_plaintext_files_are_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            body = (sim.PLAINTEXT_LINE * 4)[:128]
            for i in range(2):
                Path(tmp, f"file_{i:03d}.txt").write_bytes(body)
            self.assertTrue(sim._prepared_files_ready(tmp, 2, 128))
            self.assertFalse(sim._prepared_files_ready(tmp, 3, 128))

    def test_partial_or_wrong_content_is_not_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "file_000.txt")
            path.write_bytes(b"short")
            self.assertFalse(sim._prepared_files_ready(tmp, 1, 128))
            path.write_bytes(b"X" * 128)
            self.assertFalse(sim._prepared_files_ready(tmp, 1, 128))

    def test_permission_error_is_not_treated_as_pending(self):
        with patch.object(sim.os, "stat", side_effect=PermissionError("denied")):
            with self.assertRaises(PermissionError):
                sim._prepared_files_ready("unused", 1, 128)

    def test_finished_child_status(self):
        fake_os = SimpleNamespace(
            WNOHANG=1,
            waitpid=lambda *args: (123, 0),
            waitstatus_to_exitcode=lambda status: status,
        )
        with patch.object(sim, "os", fake_os):
            self.assertTrue(sim._wait_for_child(123, 1, "test"))
        fake_os.waitpid = lambda *args: (123, 1)
        with patch.object(sim, "os", fake_os):
            self.assertFalse(sim._wait_for_child(123, 1, "test"))

    def test_stopped_child_timeout_is_reaped(self):
        fake_os = SimpleNamespace(WNOHANG=1)
        with (
            patch.object(
                fake_os, "waitpid", side_effect=[(0, 0), (123, 0)], create=True
            ) as waitpid,
            patch.object(fake_os, "kill", create=True) as kill,
            patch.object(sim, "os", fake_os),
            patch.object(sim, "signal", SimpleNamespace(SIGKILL=9)),
            patch.object(sim.time, "monotonic", side_effect=[0, 2]),
        ):
            self.assertFalse(sim._wait_for_child(123, 1, "test"))
            kill.assert_called_once_with(123, sim.signal.SIGKILL)
            self.assertEqual(waitpid.call_args.args, (123, 0))

    def test_visibility_failure_never_starts_attack_or_deletes_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = SimpleNamespace(
                target=tmp,
                files=1,
                size_kb=1,
                chunk_kb=1,
                prepare_timeout=0.1,
                keep=False,
            )
            with (
                patch.object(sim, "parse_args", return_value=args),
                patch.object(sim, "prepare_files", return_value=True),
                patch.object(sim, "wait_for_prepared_files", return_value=False),
                patch.object(sim, "overwrite_with_random") as attack,
            ):
                self.assertEqual(sim.main(), 1)
                attack.assert_not_called()
            self.assertEqual(len(list(Path(tmp).glob("sim_hi_*"))), 1)

    def test_invalid_sizes_and_timeout_are_rejected(self):
        for option, value in (
            ("--chunk-kb", "0"),
            ("--files", "0"),
            ("--prepare-timeout", "nan"),
            ("--prepare-timeout", "0"),
        ):
            with (
                self.subTest(option=option, value=value),
                patch.object(sim.sys, "stderr", io.StringIO()),
                patch.object(sim.sys, "argv", [str(SOURCE), "unused", option, value]),
            ):
                with self.assertRaises(SystemExit) as error:
                    sim.parse_args()
                self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
