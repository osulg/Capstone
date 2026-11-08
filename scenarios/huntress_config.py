"""Huntress 일반 읽기 모드의 공통 실행 설정."""

from pathlib import Path

from experiments.simulators.sim_scn_huntress import CRED_FILES, lib

READ_FILES = tuple(CRED_FILES)
FILE_SIZE = max(len(lib.PLAINTEXT_LINE), 256)
READ_PASSES = 1
READ_DELAY_SECONDS = 0.1
PREPARE_TIMEOUT_SECONDS = 30.0

# 기존 외부 timeout 명령의 전체 실행 제한 기준.
TOTAL_TIMEOUT_SECONDS = 120.0

WORKER_PYTHON = Path(__file__).resolve().parents[1] / "venv" / "bin" / "python3"


def expected_content() -> bytes:
    """기존 simulator의 평문 준비 함수와 동일한 내용을 생성한다."""
    line = lib.PLAINTEXT_LINE
    return (line * (FILE_SIZE // len(line) + 1))[:FILE_SIZE]
