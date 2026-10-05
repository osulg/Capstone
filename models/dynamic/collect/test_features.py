"""features.py 단위 테스트: python3 -m pytest models/dynamic/collect/test_features.py"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from features import compute_features, merge_entropy  # noqa: E402

SEC = 1_000_000_000


def ev(ts, op, path=None, new_path=None, size=None, entropy=None, pid=100):
    return {"ts_ns": ts * SEC if ts < 1000 else ts, "op": op, "path": path,
            "new_path": new_path, "size": size, "entropy": entropy, "pid": pid}


def test_rates_use_duration_and_min_window():
    # 10초 구간에 write 20회 → 2/s (ts는 0~10초 사이에 분포)
    recs = [ev(0, "WRITE", "/a", size=10), ev(10, "WRITE", "/z", size=10)]
    recs += [ev(5, "WRITE", f"/f{i}", size=10) for i in range(18)]
    f = compute_features(recs)
    assert f["duration_sec"] == 10.0
    assert f["write_per_sec"] == 2.0  # 20/10

    # 매우 짧은 실행은 1초 최소창으로 나눠 총량 폭주를 막는다
    burst = [ev(0, "WRITE", f"/f{i}", size=1) for i in range(50)]
    fb = compute_features(burst)
    assert fb["duration_sec"] == 0.0
    assert fb["write_per_sec"] == 50.0  # 50/1, 50/0 아님


def test_high_entropy_ratio_only_over_entropy_writes():
    recs = [
        ev(0, "WRITE", "/a", size=100, entropy=7.5),
        ev(1, "WRITE", "/b", size=100, entropy=2.0),
        ev(2, "WRITE", "/c", size=100, entropy=None),  # eBPF-only, 엔트로피 없음
    ]
    f = compute_features(recs)
    assert f["entropy_available"] == 1
    assert f["high_entropy_write_count"] == 1
    assert f["high_entropy_write_ratio"] == 0.5  # 1 of 2 entropy-known writes
    assert f["mean_write_entropy"] == 4.75


def test_read_then_overwrite_and_ext_change():
    recs = [
        ev(0, "READ", "/doc.txt"),
        ev(1, "WRITE", "/doc.txt", size=5),        # 읽고 나서 덮어씀
        ev(2, "WRITE", "/fresh.txt", size=5),      # 읽지 않은 새 파일
        ev(3, "RENAME", "/doc.txt", "/doc.txt.locked"),  # 확장자 변경
        ev(4, "RENAME", "/x.txt", "/y.txt"),       # 확장자 동일
    ]
    f = compute_features(recs)
    assert f["read_then_overwrite_ratio"] == 0.5   # 1 of 2 writes
    assert f["ext_change_rename_ratio"] == 0.5     # 1 of 2 renames
    assert f["distinct_ext_after_rename"] == 1     # .locked


def test_spread_and_write_bytes():
    recs = [
        ev(0, "WRITE", "/d1/a", size=100),
        ev(1, "WRITE", "/d1/b", size=300),
        ev(2, "WRITE", "/d2/c", size=200),
    ]
    f = compute_features(recs)
    assert f["unique_files_touched"] == 3
    assert f["unique_dirs_touched"] == 2
    assert f["total_write_bytes"] == 600
    assert f["mean_write_bytes"] == 200.0


def test_entropy_only_features_absent_without_fuse():
    recs = [ev(0, "WRITE", "/a", size=10), ev(1, "WRITE", "/b", size=10)]
    f = compute_features(recs)
    assert f["entropy_available"] == 0
    assert f["high_entropy_write_count"] == 0
    assert f["mean_write_entropy"] == 0.0


def test_merge_entropy_matches_by_pid_path_in_order():
    ebpf = [
        ev(5, "WRITE", "/a", size=10),
        ev(6, "WRITE", "/a", size=10),
        ev(7, "WRITE", "/b", size=10),
    ]
    fuse = [
        {"ts_ns": 1, "op": "WRITE", "path": "/a", "entropy": 7.9, "pid": 100},
        {"ts_ns": 2, "op": "WRITE", "path": "/a", "entropy": 1.0, "pid": 100},
        {"ts_ns": 3, "op": "WRITE", "path": "/b", "entropy": 6.0, "pid": 100},
        {"ts_ns": 4, "op": "READ", "path": "/a", "entropy": None, "pid": 100},
    ]
    merged = merge_entropy(ebpf, fuse)
    got = [(m["path"], m["entropy"]) for m in merged]
    assert got == [("/a", 7.9), ("/a", 1.0), ("/b", 6.0)]


def test_merge_entropy_noop_without_fuse():
    ebpf = [ev(0, "WRITE", "/a", size=1)]
    assert merge_entropy(ebpf, []) is ebpf
