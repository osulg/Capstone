"""
샘플 단위 행동 피처 계산 (정상·악성 공용, 스키마 v1 레코드 입력).

한 샘플 = 한 번의 실행(부모 프로세스 + 모든 자손). PID 하나가 아니다.
피처는 총 이벤트 수만으로 정상/악성이 갈리지 않도록 비율·속도 위주로 만든다.
(문제 2-1: "이벤트가 많으면 악성"이 되면 실패)

금지 피처: 절대 경로 문자열, 실험 환경 종속 신호(Is_Test_Path, is_dev 등).
경로는 비율(확장자 변경 등)과 고유 개수 산출에만 쓰고 값 자체를 피처로 넣지 않는다.
"""

import os
import posixpath

HIGH_ENTROPY = 7.0

# 파일을 변형하는 연산(고유 파일/디렉터리 확산 계산 대상)
MUTATING_OPS = {"WRITE", "CREATE", "RENAME", "UNLINK", "TRUNCATE", "CHMOD"}

FEATURE_ORDER = [
    "duration_sec",
    "total_events",
    # 속도 (초당) — 총량이 아니라 강도를 본다
    "write_per_sec",
    "unlink_per_sec",
    "rename_per_sec",
    "create_per_sec",
    # 비율 — 행동의 성격
    "write_ratio",
    "unlink_ratio",
    "rename_ratio",
    "read_ratio",
    # 엔트로피 (FUSE 있을 때만 유효)
    "high_entropy_write_count",
    "high_entropy_write_ratio",
    "mean_write_entropy",
    "entropy_available",
    # 랜섬웨어 특유의 결합 패턴
    "read_then_overwrite_ratio",
    "ext_change_rename_ratio",
    "distinct_ext_after_rename",
    # 확산 범위
    "unique_files_touched",
    "unique_dirs_touched",
    "files_per_dir",
    # 쓰기량
    "total_write_bytes",
    "mean_write_bytes",
    # 프로세스
    "proc_count",
    "crypto_calls",
]


def _ext(path):
    if not path:
        return ""
    return posixpath.splitext(path)[1].lower()


def _safe_div(a, b):
    return a / b if b else 0.0


def compute_features(records) -> dict:
    """정렬 여부와 무관하게 동작하도록 내부에서 ts로 정렬한다."""
    evs = sorted(records, key=lambda r: r.get("ts_ns", 0))

    op_counts = {}
    read_paths = set()
    read_then_overwrite = 0
    write_events = 0

    ext_change_renames = 0
    total_renames = 0
    new_exts = set()

    touched_files = set()
    touched_dirs = set()

    write_bytes = 0
    write_size_samples = 0

    he_write = 0
    entropy_writes = 0
    entropy_sum = 0.0
    entropy_available = False

    procs = set()
    crypto = 0

    for e in evs:
        op = e.get("op")
        op_counts[op] = op_counts.get(op, 0) + 1

        pid = e.get("pid")
        if pid is not None:
            procs.add(pid)

        path = e.get("path")

        if op in MUTATING_OPS and path:
            touched_files.add(path)
            touched_dirs.add(posixpath.dirname(path))

        if op == "READ" and path:
            read_paths.add(path)

        elif op == "WRITE":
            write_events += 1
            if path and path in read_paths:
                read_then_overwrite += 1

            size = e.get("size")
            if isinstance(size, (int, float)) and size >= 0:
                write_bytes += size
                write_size_samples += 1

            ent = e.get("entropy")
            if ent is not None:
                entropy_available = True
                entropy_writes += 1
                entropy_sum += ent
                if ent >= HIGH_ENTROPY:
                    he_write += 1

        elif op == "RENAME":
            total_renames += 1
            old_ext = _ext(path)
            new_ext = _ext(e.get("new_path"))
            if e.get("new_path") and old_ext != new_ext:
                ext_change_renames += 1
                new_exts.add(new_ext)

        elif op == "CRYPTO":
            crypto += 1

    first = evs[0]["ts_ns"] if evs else 0
    last = evs[-1]["ts_ns"] if evs else 0
    duration = max((last - first) / 1e9, 0.0)
    total = len(evs)

    n_write = op_counts.get("WRITE", 0)
    n_unlink = op_counts.get("UNLINK", 0)
    n_rename = op_counts.get("RENAME", 0)
    n_create = op_counts.get("CREATE", 0)
    n_read = op_counts.get("READ", 0)

    # 실행이 매우 짧으면 속도 대신 총량이 튀므로 최소 창(1초)으로 나눈다.
    denom = max(duration, 1.0)

    return {
        "duration_sec": round(duration, 4),
        "total_events": total,
        "write_per_sec": round(_safe_div(n_write, denom), 4),
        "unlink_per_sec": round(_safe_div(n_unlink, denom), 4),
        "rename_per_sec": round(_safe_div(n_rename, denom), 4),
        "create_per_sec": round(_safe_div(n_create, denom), 4),
        "write_ratio": round(_safe_div(n_write, total), 4),
        "unlink_ratio": round(_safe_div(n_unlink, total), 4),
        "rename_ratio": round(_safe_div(n_rename, total), 4),
        "read_ratio": round(_safe_div(n_read, total), 4),
        "high_entropy_write_count": he_write,
        "high_entropy_write_ratio": round(_safe_div(he_write, entropy_writes), 4),
        "mean_write_entropy": round(_safe_div(entropy_sum, entropy_writes), 4),
        "entropy_available": int(entropy_available),
        "read_then_overwrite_ratio": round(_safe_div(read_then_overwrite, write_events), 4),
        "ext_change_rename_ratio": round(_safe_div(ext_change_renames, total_renames), 4),
        "distinct_ext_after_rename": len(new_exts),
        "unique_files_touched": len(touched_files),
        "unique_dirs_touched": len(touched_dirs),
        "files_per_dir": round(_safe_div(len(touched_files), len(touched_dirs)), 4),
        "total_write_bytes": write_bytes,
        "mean_write_bytes": round(_safe_div(write_bytes, write_size_samples), 2),
        "proc_count": len(procs),
        "crypto_calls": crypto,
    }


def merge_entropy(ebpf_records, fuse_records):
    """
    eBPF WRITE 이벤트에 FUSE의 엔트로피를 채운다.
    같은 (pid, path)의 FUSE WRITE를 시간 순서대로 대응시킨다.
    FUSE 로그가 없으면 eBPF 레코드를 그대로 돌려준다(엔트로피 None).
    """
    if not fuse_records:
        return ebpf_records

    from collections import defaultdict, deque

    queues = defaultdict(deque)
    for r in sorted(fuse_records, key=lambda r: r.get("ts_ns", 0)):
        if r.get("op") == "WRITE" and r.get("entropy") is not None:
            queues[(r.get("pid"), r.get("path"))].append(r["entropy"])

    merged = []
    for r in sorted(ebpf_records, key=lambda r: r.get("ts_ns", 0)):
        if r.get("op") == "WRITE":
            q = queues.get((r.get("pid"), r.get("path")))
            if q:
                r = dict(r)
                r["entropy"] = q.popleft()
        merged.append(r)

    return merged
