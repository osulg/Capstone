#!/usr/bin/env python3
"""
정상 워크로드 수집 러너 (Task 4).

전제: 다른 터미널에서 GuardFS가 수집 모드로 마운트돼 있어야 한다.
      (--collect-only, 마운트 = --mount 인자)
      그래야 실행 1회에 대해 FUSE 로그와 eBPF 로그가 같은 run_id로 함께 남는다.

이 러너는 각 (워크로드 × 파일 개수 × 파일 크기 × 반복)마다:
  1. 마운트 안에 실행 전용 디렉터리를 만든다
  2. 씨앗 입력 파일을 준비한다(수집 시작 전이라 추적/기록되지 않음)
  3. ebpf_collector.py로 워크로드를 실행한다 (프로세스 트리만 추적)
  4. run 메타데이터 한 줄을 CSV에 append 한다 (label=benign)

run_id 형식: benign_<workload>_<files>x<size_kb>k_<repeat>

root로 실행하고, 워크로드는 --as-user 사용자 권한으로 돌리는 것을 권장한다.
"""

import argparse
import csv
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import benign_workloads as bw  # noqa: E402

COLLECTOR = os.path.join(HERE, "ebpf_collector.py")
META_FIELDS = [
    "run_id", "label", "workload", "files", "size_kb", "repeat",
    "start_wall", "end_wall", "duration_sec", "collector_rc", "status",
]


def parse_args():
    p = argparse.ArgumentParser(description="정상 워크로드 수집 러너")
    p.add_argument("--mount", required=True, help="수집 모드 GuardFS 마운트 경로")
    p.add_argument("--out-csv", help="run 메타데이터 CSV (기본: 마운트 옆 collect/benign_runs.csv)")
    p.add_argument("--as-user", help="워크로드 실행 사용자 (root로 러너를 돌릴 때 권장)")
    p.add_argument("--repeats", type=int, default=3, help="각 조합 반복 횟수")
    p.add_argument("--files", default="10,100,1000", help="파일 개수 목록")
    p.add_argument("--sizes", default="4,256", help="파일 크기(KB) 목록")
    p.add_argument("--workloads", help="쉼표로 구분한 워크로드 이름(기본: 사용 가능한 전부)")
    p.add_argument("--timeout", type=float, default=300.0, help="워크로드 1회 최대 시간(초)")
    p.add_argument("--cleanup", action="store_true",
                   help="각 run 종료 후 워크로드 데이터 삭제 (로그는 유지, 디스크 절약)")
    p.add_argument("--dry-run", action="store_true", help="실행 계획만 출력")
    return p.parse_args()


def main():
    args = parse_args()
    mount = os.path.realpath(args.mount)

    if not os.path.ismount(mount) and not args.dry_run:
        print(f"[run_benign] 경고: {mount} 가 마운트 지점이 아닙니다. "
              f"GuardFS 수집 모드가 켜져 있는지 확인하세요.", file=sys.stderr)

    names = args.workloads.split(",") if args.workloads else None
    workloads = bw.available(names)
    skipped = bw.missing(names)

    for name, absent in skipped.items():
        print(f"[run_benign] 건너뜀 {name}: 도구 없음 {absent}")

    counts = [int(x) for x in args.files.split(",")]
    sizes = [int(x) for x in args.sizes.split(",")]

    out_csv = args.out_csv or os.path.join(
        os.path.dirname(mount), "collect", "benign_runs.csv"
    )
    os.makedirs(os.path.dirname(out_csv), exist_ok=True)
    new_file = not os.path.exists(out_csv)

    plan = [
        (name, builder, n, kb, r)
        for name, builder in workloads.items()
        for n in counts
        for kb in sizes
        for r in range(1, args.repeats + 1)
    ]
    print(f"[run_benign] 워크로드 {len(workloads)}종 × 개수 {counts} × 크기 {sizes} "
          f"× 반복 {args.repeats} = 총 {len(plan)} run")

    if args.dry_run:
        for name, _b, n, kb, r in plan:
            print(f"  benign_{name}_{n}x{kb}k_{r}")
        return 0

    csv_f = open(out_csv, "a", newline="", encoding="utf-8")
    writer = csv.DictWriter(csv_f, fieldnames=META_FIELDS)
    if new_file:
        writer.writeheader()

    done = 0
    for name, builder, n, kb, r in plan:
        run_id = f"benign_{name}_{n}x{kb}k_{r}"
        workdir = os.path.join(mount, "runs", run_id)

        status = "ok"
        rc = None
        start = time.time()
        start_wall = time.strftime("%Y-%m-%dT%H:%M:%S%z")

        try:
            # 이전 실행(같은 run_id)이 남긴 파일을 먼저 제거한다. 안 그러면
            # gzip/sqlite 등이 기존 파일과 충돌해 프롬프트에서 멈추거나 실패한다.
            shutil.rmtree(workdir, ignore_errors=True)
            os.makedirs(workdir, exist_ok=True)
            command = builder(workdir, n, kb)  # 씨앗 준비 + 실행 argv
            if args.as_user:
                _chown_tree(workdir, args.as_user)

            cmd = [
                sys.executable, COLLECTOR,
                "--run-id", run_id,
                "--target-dir", mount,
                "--timeout", str(args.timeout),
            ]
            if args.as_user:
                cmd += ["--as-user", args.as_user]
            cmd += ["--"] + command

            rc = subprocess.run(cmd, timeout=args.timeout + 60).returncode
            if rc != 0:
                status = f"collector_rc={rc}"
        except subprocess.TimeoutExpired:
            status = "timeout"
        except Exception as e:  # noqa: BLE001 - run 하나 실패가 전체를 멈추지 않게
            status = f"error:{type(e).__name__}:{e}"
        finally:
            # 로그는 이미 collect/ 에 저장됐으므로 워크로드가 만든 데이터는 지워도 된다.
            # 수백 run에서 디스크가 계속 차오르는 것을 막는다.
            if args.cleanup:
                shutil.rmtree(workdir, ignore_errors=True)

        writer.writerow({
            "run_id": run_id, "label": "benign", "workload": name,
            "files": n, "size_kb": kb, "repeat": r,
            "start_wall": start_wall,
            "end_wall": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "duration_sec": round(time.time() - start, 3),
            "collector_rc": rc, "status": status,
        })
        csv_f.flush()

        done += 1
        print(f"[run_benign] ({done}/{len(plan)}) {run_id} -> {status}")

    csv_f.close()
    print(f"[run_benign] 완료. 메타데이터: {out_csv}")
    return 0


def _chown_tree(path, user):
    import pwd
    pw = pwd.getpwnam(user)
    for root, dirs, fnames in os.walk(path):
        os.chown(root, pw.pw_uid, pw.pw_gid)
        for name in dirs + fnames:
            try:
                os.chown(os.path.join(root, name), pw.pw_uid, pw.pw_gid)
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
