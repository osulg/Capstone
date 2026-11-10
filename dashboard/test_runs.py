"""실행별 폴더 스캔(/api/runs) 테스트: 임시 폴더를 보호 폴더로 써서 확인한다."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import files as file_scan  # noqa: E402

PLAIN = b"This is a plain text test document for GuardFS simulation.\n" * 80
RUN_A = "s04_" + "a" * 32
RUN_B = "s01_" + "b" * 32


def _setup(tmp_path, monkeypatch):
    root = tmp_path / "underlay"
    (root / RUN_A).mkdir(parents=True)
    (root / RUN_B).mkdir()
    (root / "honeypot").mkdir()
    (root / "sim_icefire").mkdir()
    for i in range(3):
        (root / RUN_A / f"file_{i:03d}.txt").write_bytes(PLAIN)
    # 암호화된 파일 2개 (하나는 확장자가 바뀌었고 하나는 그대로) + 확장자만 바뀐 평문 1개
    (root / RUN_A / "file_003.txt.sb0nji").write_bytes(os.urandom(4096))
    (root / RUN_A / "file_004.txt").write_bytes(os.urandom(4096))
    (root / RUN_A / "file_005.txt.sb0nji").write_bytes(PLAIN)
    (root / RUN_B / "doc.txt").write_bytes(PLAIN)
    (root / "honeypot" / "id_rsa").write_bytes(b"DUMMY DECOY\n")
    monkeypatch.setitem(file_scan._folder("protected"), "path", str(root))
    return root


def test_list_runs_counts_entropy_only(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    data = file_scan.list_runs()
    names = [r["name"] for r in data["runs"]]
    assert sorted(names) == sorted([RUN_A, RUN_B])  # honeypot, sim_* 폴더는 제외
    run = next(r for r in data["runs"] if r["name"] == RUN_A)
    assert run["scenario"] == "S04" and run["label"] == "S04 LOLBin"
    assert run["total"] == 6
    assert run["suspect"] == 2   # 확장자만 바뀐 평문은 세지 않는다
    assert run["ok"] == 4


def test_scan_run_returns_files_with_previewable_paths(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    data = file_scan.scan_run(RUN_A)
    assert data["summary"]["suspect"] == 2
    paths = [f["path"] for f in data["files"]]
    assert f"{RUN_A}/file_003.txt.sb0nji" in paths
    assert file_scan.preview("protected", paths[0]) is not None


def test_scan_run_rejects_bad_names(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    for name in ("", "honeypot", "sim_icefire", "../etc", "s05_" + "a" * 32, RUN_A + "/x"):
        assert file_scan.scan_run(name) is None
    assert file_scan.scan_run("s02_" + "c" * 32) is None  # 형식은 맞지만 없음
