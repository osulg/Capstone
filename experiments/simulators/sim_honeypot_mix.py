#!/usr/bin/env python3
"""
고엔트로피 덮어쓰기 + 허니팟 접근 혼합 시뮬레이터 (GuardFS 탐지 테스트용).

실제 랜섬웨어가 아니다. 암호화·키 관리·랜섬노트가 없고, 이 스크립트가 직접
만든 테스트 파일(대상 폴더 아래 sim_hp_<시각> 하위 폴더)에만 난수를 쓴다.
허니팟 파일은 읽기/쓰기 "시도"만 하며 GuardFS가 거부하면 그대로 넘어간다.

sim_highentropy.py 와 같은 방식으로 파일을 준비·덮어쓰되, 폴더를 훑는 공격처럼
중간중간 허니팟 디렉터리의 미끼 파일에 접근한다:
  1) 자식 프로세스가 평문 파일 N개를 만들고 종료한다 (피해 파일 준비, PID 분리).
  2) 공격 역할 프로세스가 먼저 허니팟을 정찰(목록 조회 + 미끼 파일 열기 시도)한다.
  3) 파일을 하나씩 읽고 난수로 덮어쓴 뒤 확장자를 바꾼다.
     --honeypot-every 개마다 미끼 파일 읽기/쓰기를 다시 시도한다.
  4) 대상 파일 쓰기가 거부되면(HIGH 차단) 멈추고, 결과를 요약한다.

사용 (GuardFS를 탐지 모드로 띄운 뒤, 마운트 안의 경로로):
  python3 experiments/simulators/sim_honeypot_mix.py ~/guardfs_runtime/mount/sim_target --keep

미끼 파일이 없으면 허니팟 접근은 건너뛴다. 미리 만들어 두려면 (GuardFS를 거치지 않도록 underlay에):
  mkdir -p ~/guardfs_runtime/underlay/honeypot
  echo "decoy" > ~/guardfs_runtime/underlay/honeypot/salary_2026.xlsx

참고: GuardFS가 HIGH로 판정하면 이 프로세스는 SIGSTOP 으로 멈출 수 있다
      (오류 없이 출력이 멈춘다). Ctrl+Z 후 kill -9 %% 로 정리할 것.
"""

import argparse
import errno
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sim_highentropy import overwrite_with_random, prepare_files  # noqa: E402

DEFAULT_HONEYPOT = os.path.expanduser("~/guardfs_runtime/mount/honeypot")


def parse_args():
    p = argparse.ArgumentParser(description="고엔트로피 덮어쓰기 + 허니팟 접근 혼합 시뮬레이터")
    p.add_argument("target", help="GuardFS 마운트 안의 대상 폴더 (없으면 생성)")
    p.add_argument("--honeypot-dir", default=DEFAULT_HONEYPOT,
                   help=f"마운트 경로 기준 허니팟 폴더 (기본: {DEFAULT_HONEYPOT})")
    p.add_argument("--honeypot-every", type=int, default=5,
                   help="파일 몇 개마다 허니팟 접근을 시도할지 (0이면 정찰 1회만)")
    p.add_argument("--files", type=int, default=20, help="테스트 파일 개수")
    p.add_argument("--size-kb", type=int, default=64, help="파일당 크기(KB)")
    p.add_argument("--chunk-kb", type=int, default=16, help="한 번에 쓰는 난수 크기(KB)")
    p.add_argument("--rename-ext", default=".locked",
                   help="덮어쓴 뒤 붙일 확장자. 빈 문자열이면 rename 안 함")
    p.add_argument("--delay", type=float, default=0.15, help="파일 간 대기(초)")
    p.add_argument("--keep", action="store_true", help="종료 후 테스트 파일을 지우지 않음")
    return p.parse_args()


def _err(e: OSError) -> str:
    return errno.errorcode.get(e.errno, str(e.errno))


def touch_honeypot(hp_dir: str, decoys: list, round_no: int, stats: dict) -> None:
    """미끼 파일 하나에 읽기, 다음 하나에 쓰기를 시도한다. 거부되면 기록만 하고 계속한다."""
    if not decoys:
        return
    for mode, name in (("read", decoys[round_no % len(decoys)]),
                       ("write", decoys[(round_no + 1) % len(decoys)])):
        path = os.path.join(hp_dir, name)
        stats["hp_attempts"] += 1
        try:
            if mode == "read":
                with open(path, "rb") as f:
                    f.read(256)
            else:
                with open(path, "r+b") as f:
                    f.write(os.urandom(64))
            stats["hp_allowed"] += 1
            print(f"[SIM]   허니팟 {mode:<5} {name} → 허용됨 (!)")
        except OSError as e:
            stats["hp_blocked"] += 1
            print(f"[SIM]   허니팟 {mode:<5} {name} → 거부됨 ({_err(e)})")


def main():
    args = parse_args()

    target = os.path.realpath(os.path.expanduser(args.target))
    if target in ("/", os.path.realpath(os.path.expanduser("~"))):
        print("[SIM] 대상 폴더가 너무 광범위합니다. 마운트 안의 전용 폴더를 지정하세요.")
        return 2
    hp_dir = os.path.expanduser(args.honeypot_dir)
    if os.path.realpath(target).startswith(os.path.realpath(hp_dir) + os.sep):
        print("[SIM] 대상 폴더가 허니팟 안에 있습니다. 다른 폴더를 지정하세요.")
        return 2

    os.makedirs(target, exist_ok=True)
    workdir = os.path.join(target, time.strftime("sim_hp_%Y%m%d_%H%M%S"))
    os.makedirs(workdir, exist_ok=False)   # 이 스크립트가 새로 만든 폴더만 사용

    size = args.size_kb * 1024
    chunk = args.chunk_kb * 1024

    print(f"[SIM] 작업 폴더: {workdir}")
    print(f"[SIM] 준비: 평문 {args.files}개 x {args.size_kb}KB (자식 프로세스)")
    if not prepare_files(workdir, args.files, size):
        print("[SIM] 평문 준비에 실패해 종료합니다.")
        return 1

    paths = [os.path.join(workdir, f"file_{i:03d}.txt") for i in range(args.files)]
    stats = {"modified": 0, "hp_attempts": 0, "hp_blocked": 0, "hp_allowed": 0}
    print(f"[SIM] 공격 역할 PID={os.getpid()} 시작. GuardFS 로그/대시보드를 확인하세요.")

    # 정찰: 허니팟 목록 조회 (readdir 은 GuardFS가 막지 않는다)
    try:
        decoys = sorted(n for n in os.listdir(hp_dir) if not n.startswith("."))
        print(f"[SIM] 허니팟 정찰: {hp_dir} → 미끼 파일 {len(decoys)}개")
    except OSError as e:
        decoys = []
        print(f"[SIM] 허니팟 폴더를 열 수 없어 허니팟 접근은 건너뜁니다: {hp_dir} ({_err(e)})")
    touch_honeypot(hp_dir, decoys, 0, stats)

    start = time.time()
    rc = 0
    try:
        for i, path in enumerate(paths):
            overwrite_with_random(path, size, chunk)
            stats["modified"] += 1
            if args.rename_ext:
                os.rename(path, path + args.rename_ext)
            print(f"[SIM] 덮어쓰기 {stats['modified']:>3}/{len(paths)}  {os.path.basename(path)}")
            if args.honeypot_every and (i + 1) % args.honeypot_every == 0:
                touch_honeypot(hp_dir, decoys, i + 1, stats)
            if args.delay:
                time.sleep(args.delay)
    except OSError as e:
        # 대상 파일 쓰기/이름변경이 거부되면 HIGH 차단으로 보고 멈춘다.
        print(f"[SIM] 대상 파일 요청이 거부되었습니다: {e}  -> 차단된 것으로 판단하고 종료")
        rc = 3
    finally:
        print("[SIM] ---------------- 결과 ----------------")
        print(f"[SIM] 덮어쓴 파일   : {stats['modified']}/{len(paths)}")
        print(f"[SIM] 허니팟 시도   : {stats['hp_attempts']}회 "
              f"(거부 {stats['hp_blocked']}, 허용 {stats['hp_allowed']})")
        print(f"[SIM] 경과 시간     : {time.time() - start:.1f}s")
        if not args.keep:
            for name in os.listdir(workdir):
                try:
                    os.unlink(os.path.join(workdir, name))
                except OSError as e:
                    print(f"[SIM] 정리 실패(무시): {name}: {e}")
                    break
            try:
                os.rmdir(workdir)
            except OSError:
                print(f"[SIM] 작업 폴더가 남아 있습니다. 수동 삭제: {workdir}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
