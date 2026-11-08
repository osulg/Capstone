"""기존 CLI 비교 실험에 맞춘 IceFire 웹 실행 설정."""

from pathlib import Path

FILE_COUNT = 10
FILE_SIZE_KIB = 64
PREPARE_TIMEOUT_SECONDS = 30.0
ATTACK_TIMEOUT_SECONDS = 30.0
WORKER_PYTHON = Path(__file__).resolve().parents[1] / "venv" / "bin" / "python3"


def expected_operations(action: str, files: int = FILE_COUNT) -> int:
    """문서 작업과 표식·노트 작업을 포함한 예정 연산 수."""
    if action in ("prepare", "verify"):
        return files + 1
    if action == "attack":
        return files * 3 + 2
    raise ValueError("지원하지 않는 자식 작업입니다.")
