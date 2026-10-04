#!/usr/bin/env python3
"""
고엔트로피 쓰기 부하 시뮬레이터 (GuardFS 탐지 테스트용).

실제 랜섬웨어가 아니다. 암호화·키 관리·랜섬노트가 없고, 이 스크립트가 직접
만든 테스트 파일(대상 폴더 아래 sim_hi_<시각> 하위 폴더)에만 난수를 쓴다.
기존 파일은 건드리지 않는다.

랜섬웨어의 파일 행동만 흉내 낸다:
  1) 자식 프로세스가 평문 파일 N개를 만들고 종료한다 (피해 파일 준비).
     -> 준비 쓰기가 공격 PID의 프로필을 희석하지 않도록 PID를 분리한다.
  2) 공격 역할 프로세스(이 프로세스)가 파일을 읽고(read), 같은 파일을
     os.urandom 난수로 덮어쓴다(read-then-overwrite, 고엔트로피 write).
  3) --rename-ext 를 주면 덮어쓴 파일의 확장자를 바꾼다(확장자 변경 rename).
  4) --duration 초 동안 반복한다. 차단(오류)되면 즉시 종료한다.

사용 (GuardFS를 detection 모드로 띄운 뒤, 마운트 안의 경로로):
  python3 experiments/simulators/sim_highentropy.py ~/guardfs_runtime/mount/sim_target
  python3 experiments/simulators/sim_highentropy.py ~/guardfs_runtime/mount/sim_target \
      --duration 20 --files 100 --rename-ext .locked

참고: GuardFS가 HIGH로 판정하면 이 프로세스는 SIGSTOP 으로 멈출 수 있다
      (오류 없이 출력이 멈춘다). 다른 터미널에서 [STATE]/[TRIGGER HIGH] 로그로 확인할 것.
"""

import argparse
import os
import sys
import time

PLAINTEXT_LINE = b"This is a plain text test document for GuardFS simulation.\n"


def parse_args():
    p = argparse.ArgumentParser(description="고엔트로피 쓰기 부하 시뮬레이터")
    p.add_argument("target", help="GuardFS 마운트 안의 대상 폴더 (없으면 생성)")
    p.add_argument("--files", type=int, default=50, help="테스트 파일 개수")
    p.add_argument("--size-kb", type=int, default=64, help="파일당 크기(KB)")
    p.add_argument("--chunk-kb", type=int, default=16, help="한 번에 쓰는 난수 크기(KB)")
    p.add_argument("--duration", type=float, default=30.0, help="반복 시간(초)")
    p.add_argument("--rename-ext", default="",
                   help="덮어쓴 뒤 붙일 확장자 (예: .locked). 비우면 rename 안 함")
    p.add_argument("--delay", type=float, default=0.0, help="파일 간 대기(초)")
    p.add_argument("--keep", action="store_true", help="종료 후 테스트 파일을 지우지 않음")
    return p.parse_args()


def prepare_files(workdir, count, size):
    """평문 파일 생성. 별도 프로세스(fork)에서 실행해 PID를 분리한다."""
    pid = os.fork()
    if pid == 0:
        status = 0
        try:
            body = (PLAINTEXT_LINE * (size // len(PLAINTEXT_LINE) + 1))[:size]
            for i in range(count):
                with open(os.path.join(workdir, f"file_{i:03d}.txt"), "wb") as f:
                    f.write(body)
        except OSError as e:
            print(f"[SIM] 준비 실패: {e}", file=sys.stderr)
            status = 1
        os._exit(status)
    _, st = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(st) == 0


def overwrite_with_random(path, size, chunk):
    """파일을 읽고(read-then-overwrite), 같은 위치부터 난수로 덮어쓴다."""
    with open(path, "rb") as f:
        f.read()
    fd = os.open(path, os.O_WRONLY)
    try:
        written = 0
        while written < size:
            n = min(chunk, size - written)
            written += os.write(fd, os.urandom(n))
    finally:
        os.close(fd)
    return written


def main():
    args = parse_args()

    target = os.path.realpath(os.path.expanduser(args.target))
    if target in ("/", os.path.realpath(os.path.expanduser("~"))):
        print("[SIM] 대상 폴더가 너무 광범위합니다. 마운트 안의 전용 폴더를 지정하세요.")
        return 2

    os.makedirs(target, exist_ok=True)
    workdir = os.path.join(target, time.strftime("sim_hi_%Y%m%d_%H%M%S"))
    os.makedirs(workdir, exist_ok=False)   # 이 스크립트가 새로 만든 폴더만 사용

    size = args.size_kb * 1024
    chunk = args.chunk_kb * 1024

    print(f"[SIM] 작업 폴더: {workdir}")
    print(f"[SIM] 준비: 평문 {args.files}개 x {args.size_kb}KB (자식 프로세스)")
    if not prepare_files(workdir, args.files, size):
        print("[SIM] 평문 준비에 실패해 종료합니다.")
        return 1

    paths = [os.path.join(workdir, f"file_{i:03d}.txt") for i in range(args.files)]
    print(f"[SIM] 공격 역할 PID={os.getpid()} 시작 (duration={args.duration}s). "
          f"GuardFS 로그를 확인하세요.")

    start = time.time()
    total_bytes = 0
    passes = 0
    rc = 0
    try:
        while time.time() - start < args.duration:
            for i, path in enumerate(paths):
                total_bytes += overwrite_with_random(path, size, chunk)
                if args.rename_ext and not path.endswith(args.rename_ext):
                    new_path = path + args.rename_ext
                    os.rename(path, new_path)
                    paths[i] = new_path
                if args.delay:
                    time.sleep(args.delay)
                if time.time() - start >= args.duration:
                    break
            passes += 1
            print(f"[SIM] pass {passes} 완료  누적 {total_bytes / 1024 / 1024:.1f}MB  "
                  f"{time.time() - start:.1f}s")
    except OSError as e:
        # GuardFS가 쓰기/읽기를 거부하면 차단된 것으로 보고 멈춘다.
        print(f"[SIM] 요청이 거부되었습니다: {e}  -> 차단된 것으로 판단하고 종료")
        rc = 3
    finally:
        print(f"[SIM] 종료: {passes} pass, 누적 {total_bytes / 1024 / 1024:.1f}MB, "
              f"{time.time() - start:.1f}s")
        if not args.keep:
            for name in os.listdir(workdir):
                try:
                    os.unlink(os.path.join(workdir, name))
                except OSError as e:
                    # 차단 상태에서는 삭제도 거부될 수 있다. 남은 파일은 수동 정리.
                    print(f"[SIM] 정리 실패(무시): {name}: {e}")
                    break
            try:
                os.rmdir(workdir)
            except OSError:
                print(f"[SIM] 작업 폴더가 남아 있습니다. 수동 삭제: {workdir}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
