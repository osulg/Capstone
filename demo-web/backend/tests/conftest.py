"""테스트가 실제 ~/guardfs_runtime/process_roles.jsonl 에 역할 기록을 남기지 않도록 임시 경로로 바꾼다."""

import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parents[1]
for path in (str(ROOT), str(BACKEND)):
    if path not in sys.path:
        sys.path.insert(0, path)


@pytest.fixture(autouse=True)
def _isolated_process_roles(tmp_path, monkeypatch):
    try:
        from app.services import runner
    except ImportError:  # pydantic 등이 없는 환경
        yield
        return
    monkeypatch.setattr(runner, "PROCESS_ROLES_PATH", str(tmp_path / "process_roles.jsonl"))
    yield
