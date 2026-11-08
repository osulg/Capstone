"""Akira 웹 시연 공통 설정."""

from pathlib import Path

from experiments.simulators.sim_scn_akira import (
    VM_EXTS,
    lib,
)

FILE_COUNT = 8
FILE_SIZE = 64 * 1024
ENCRYPTION_PERCENT = 20
CHUNK_SIZE = 16 * 1024
DELAY_SECONDS = 0.15

PREPARE_TIMEOUT_SECONDS = 30.0
ATTACK_TIMEOUT_SECONDS = 30.0
TOTAL_TIMEOUT_SECONDS = 120.0

WORKER_PYTHON = Path(__file__).resolve().parents[1] / "venv" / "bin" / "python3"

FILE_NAMES = tuple(
    f"vm_{index:03d}{VM_EXTS[index % len(VM_EXTS)]}" for index in range(FILE_COUNT)
)


def expected_content():
    line = lib.PLAINTEXT_LINE
    return (line * (FILE_SIZE // len(line) + 1))[:FILE_SIZE]
