"""roles.py: 웹 시연 작업 프로세스 역할 찾기 테스트"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from roles import ROLE_WINDOW_SEC, RoleIndex  # noqa: E402


def _write(path, entries):
    path.write_text("".join(json.dumps(e) + "\n" for e in entries) + "깨진 줄\n", encoding="utf-8")


def test_lookup_by_pid_and_time(tmp_path):
    f = tmp_path / "roles.jsonl"
    _write(f, [
        {"pid": 100, "start_time_ticks": 1, "role": "akira_attack", "scenario_id": "S03", "registered_ts": 1000.0},
        {"pid": 100, "start_time_ticks": 2, "role": "lolbin_attack", "scenario_id": "S04", "registered_ts": 5000.0},
    ])
    idx = RoleIndex(str(f))
    assert idx.lookup(100, 1001.0)["role"] == "akira_attack"
    assert idx.lookup(100, 5001.0)["role"] == "lolbin_attack"      # PID 재사용: 더 최근 등록
    assert idx.lookup(100, 999.0 - 10) is None                      # 등록 전 이벤트
    assert idx.lookup(100, 5000.0 + ROLE_WINDOW_SEC + 1) is None     # 너무 오래 지난 이벤트
    assert idx.lookup(200, 1001.0) is None


def test_missing_file_and_reload(tmp_path):
    f = tmp_path / "roles.jsonl"
    idx = RoleIndex(str(f))
    assert idx.lookup(1, 1.0) is None
    _write(f, [{"pid": 1, "role": "icefire_attack", "registered_ts": 1.0}])
    assert idx.lookup(1, 2.0)["role"] == "icefire_attack"


def test_server_replaces_process_name_with_role(tmp_path, monkeypatch):
    import server
    f = tmp_path / "roles.jsonl"
    _write(f, [{"pid": 4242, "role": "lolbin_attack", "scenario_id": "S04", "registered_ts": 1000.0}])
    monkeypatch.setattr(server, "roles", RoleIndex(str(f)))
    ev = server._normalize({"pid": 4242, "process": "python3", "ts": 1005.0, "level": "HIGH"})
    assert (ev["process"], ev["comm"], ev["scenario"]) == ("lolbin_attack", "python3", "S04")
    other = server._normalize({"pid": 7, "process": "python3", "ts": 1005.0})
    assert other["process"] == "python3" and "role" not in other
