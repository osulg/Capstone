#!/usr/bin/env python3
"""
고엔트로피 쓰기 부하 시뮬레이터 (GuardFS 탐지 테스트용).

실제 랜섬웨어가 아니다. 암호화·키 관리·랜섬노트가 없고, 이 스크립트가 직접
만든 테스트 파일(대상 폴더 아래 sim_hi_<시각> 하위 폴더)에만 난수를 쓴다.
기존 파일은 건드리지 않는다.

랜섬웨어의 파일 행동만 흉내 낸다:
  1) 자식 프로세스가 평문 파일 N개를 만들고 종료한다 (피해 파일 준비).
     -> 준비 쓰기가 공격 PID의 프로필을 희석하지 않도록 PID를 분리한다.
     -> 별도 확인 PID에서 파일 공개와 평문 내용을 검증한 뒤 공격을 시작한다.
        준비/확인 시간 초과 시 공격하지 않고 진단용 작업 폴더를 보존한다.
  2) 공격 역할 프로세스(이 프로세스)가 파일을 읽고(read), 같은 파일을
     os.urandom 난수로 덮어쓴다(read-then-overwrite, 고엔트로피 write).
  3) --rename-ext 를 주면 덮어쓴 파일의 확장자를 바꾼다(확장자 변경 rename).
  4) --passes 번(기본 1) 반복하되 --duration 초를 넘기지 않는다. 차단되면 즉시 종료한다.

기본값(파일 20개 x 64KB, 1 pass, rename 포함)은 동적 모델 v5의 학습 분포와
비슷한 규모다. 같은 파일을 수십 pass 반복하거나 파일을 수백 개로 늘리면
총 쓰기량이 학습 분포를 크게 벗어나 점수가 오히려 낮아질 수 있다.

테스트 방법 (Linux/Ubuntu, 터미널 두 개 사용):
  1) 터미널 A에서 GuardFS를 detection 모드로 실행하고 mount 성공을 확인한다.
     이미 실행 중이면 기존 GuardFS 터미널에서 로그를 확인한다.
       cd ~/Capstone
       bash scripts/run_guardfs.sh
  2) 터미널 B에서 가상환경과 mount 상태를 확인한 뒤 실행한다.
       cd ~/Capstone
       source venv/bin/activate
       mountpoint ~/guardfs_runtime/mount
       python3 experiments/simulators/sim_highentropy.py ~/guardfs_runtime/mount/sim_target --prepare-timeout 60 --keep

확인 기준:
  - 준비 PID와 공개 확인 PID가 출력되고, '준비 완료' 다음에 공격 PID가
    출력되어야 한다. 준비 시간 초과/실패 시에는 공격을 시작하지 않는다.
  - 공격 시작 후 터미널 A에서 해당 공격 PID의 상태와 탐지 사유를 확인한다.
    [STATE]/[TRIGGER HIGH]의 HIGH 전환 및 suspend 로그를 대조한다.
  - HIGH 정책의 SIGSTOP으로 셸에 'Stopped'가 표시될 수 있다. 정지는 종료가
    아니며, 이 메시지만으로 GuardFS 탐지 성공을 단정하지 않는다.
  - ENOENT 등 파일 오류는 상태/이벤트 로그와 함께 원인을 확인한다.
  - --keep 사용 시 출력된 전용 작업 폴더에 실험 파일을 남겨 상태를 확인한다.

준비 로직만 검사하려면 python experiments/tests/test_sim_highentropy.py를 실행한다.
"""

import argparse
import math
import os
import signal
import sys
import time

PLAINTEXT_LINE = b"This is a plain text test document for GuardFS simulation.\n"


def parse_args():
    p = argparse.ArgumentParser(description="고엔트로피 쓰기 부하 시뮬레이터")
    p.add_argument("target", help="GuardFS 마운트 안의 대상 폴더 (없으면 생성)")
    p.add_argument("--files", type=int, default=20, help="테스트 파일 개수")
    p.add_argument("--size-kb", type=int, default=64, help="파일당 크기(KB)")
    p.add_argument(
        "--chunk-kb", type=int, default=16, help="한 번에 쓰는 난수 크기(KB)"
    )
    p.add_argument("--duration", type=float, default=30.0, help="반복 시간(초)")
    p.add_argument(
        "--passes",
        type=int,
        default=1,
        help="전체 파일을 덮어쓰는 반복 횟수 (0이면 --duration 동안 계속)",
    )
    p.add_argument(
        "--rename-ext",
        default=".locked",
        help="덮어쓴 뒤 붙일 확장자. 빈 문자열이면 rename 안 함",
    )
    p.add_argument(
        "--delay",
        type=float,
        default=0.15,
        help="파일 간 대기(초). Stage2 재평가(1초 주기)가 중간에 개입할 시간을 준다",
    )
    p.add_argument(
        "--keep", action="store_true", help="종료 후 테스트 파일을 지우지 않음"
    )
    p.add_argument(
        "--prepare-timeout",
        type=float,
        default=30.0,
        help="준비/공개 확인 단계별 최대 대기 시간(초)",
    )
    args = p.parse_args()
    if args.files <= 0 or args.size_kb <= 0 or args.chunk_kb <= 0:
        p.error("--files, --size-kb, --chunk-kb는 양수여야 합니다.")
    if args.passes < 0:
        p.error("--passes는 0 이상이어야 합니다.")
    if not math.isfinite(args.prepare_timeout) or args.prepare_timeout <= 0:
        p.error("--prepare-timeout은 유한한 양수여야 합니다.")
    if not math.isfinite(args.duration) or args.duration <= 0:
        p.error("--duration은 유한한 양수여야 합니다.")
    if not math.isfinite(args.delay) or args.delay < 0:
        p.error("--delay는 유한한 0 이상의 값이어야 합니다.")
    return args


def _wait_for_child(pid, timeout, phase):
    """SIGSTOP 또는 파일 연산 대기로 자식이 멈춰도 부모는 제한 시간 내 종료한다."""
    deadline = time.monotonic() + timeout
    while True:
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            return os.waitstatus_to_exitcode(status) == 0
        if time.monotonic() >= deadline:
            print(f"[SIM] {phase} 시간 초과: PID={pid}", file=sys.stderr, flush=True)
            try:
                # 이 시뮬레이터가 만든 자식만 종료한다. pending 파일은 삭제하지 않는다.
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)
            return False
        time.sleep(0.1)


def prepare_files(workdir, count, size, timeout=30.0):
    """평문 파일 생성. 별도 프로세스(fork)에서 실행해 PID를 분리한다."""
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid == 0:
        status = 0
        try:
            body = (PLAINTEXT_LINE * (size // len(PLAINTEXT_LINE) + 1))[:size]
            for i in range(count):
                with open(os.path.join(workdir, f"file_{i:03d}.txt"), "wb") as f:
                    f.write(body)
        except OSError as e:
            print(f"[SIM] 준비 실패: {e}", file=sys.stderr, flush=True)
            status = 1
        os._exit(status)
    print(f"[SIM] 준비 PID={pid}", flush=True)
    return _wait_for_child(pid, timeout, "평문 준비")


def _prepared_files_ready(workdir, count, size):
    """공개된 파일의 크기와 평문을 확인한다. pending ENOENT는 재시도한다."""
    body = (PLAINTEXT_LINE * (size // len(PLAINTEXT_LINE) + 1))[:size]
    for i in range(count):
        path = os.path.join(workdir, f"file_{i:03d}.txt")
        try:
            if os.stat(path).st_size != size:
                return False
            with open(path, "rb") as handle:
                if handle.read(size + 1) != body:
                    return False
        except FileNotFoundError:
            return False
    return True


def wait_for_prepared_files(workdir, count, size, timeout):
    """확인 접근은 별도 PID에서 실행하여 공격 PID의 ML 프로필을 보존한다."""
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid == 0:
        status = 1
        try:
            deadline = time.monotonic() + timeout
            while True:
                if _prepared_files_ready(workdir, count, size):
                    status = 0
                    break
                if time.monotonic() >= deadline:
                    print(
                        "[SIM] 준비 파일 공개 시간 초과: commit/drop 및 상태 로그를 확인하세요.",
                        file=sys.stderr,
                        flush=True,
                    )
                    break
                time.sleep(0.1)
        except OSError as e:
            print(f"[SIM] 준비 확인 실패: {e}", file=sys.stderr, flush=True)
        finally:
            os._exit(status)
    print(f"[SIM] 공개 확인 PID={pid}", flush=True)
    return _wait_for_child(pid, timeout, "준비 파일 공개 확인")


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
        print(
            "[SIM] 대상 폴더가 너무 광범위합니다. 마운트 안의 전용 폴더를 지정하세요."
        )
        return 2

    os.makedirs(target, exist_ok=True)
    workdir = os.path.join(target, time.strftime("sim_hi_%Y%m%d_%H%M%S"))
    os.makedirs(workdir, exist_ok=False)  # 이 스크립트가 새로 만든 폴더만 사용

    size = args.size_kb * 1024
    chunk = args.chunk_kb * 1024

    print(f"[SIM] 작업 폴더: {workdir}")
    print(f"[SIM] 준비: 평문 {args.files}개 x {args.size_kb}KB (자식 프로세스)")
    if not prepare_files(workdir, args.files, size, args.prepare_timeout):
        print(f"[SIM] 평문 준비 실패. 공격 미시작; 진단용 폴더 보존: {workdir}")
        return 1

    print("[SIM] 준비 파일의 공개 완료를 기다립니다.", flush=True)
    if not wait_for_prepared_files(workdir, args.files, size, args.prepare_timeout):
        print(f"[SIM] 준비 확인 실패. 공격 미시작; 진단용 폴더 보존: {workdir}")
        return 1

    print("[SIM] 준비 완료: 다른 PID에서 파일 크기와 평문 내용 확인", flush=True)
    paths = [os.path.join(workdir, f"file_{i:03d}.txt") for i in range(args.files)]
    print(
        f"[SIM] 공격 역할 PID={os.getpid()} 시작 (duration={args.duration}s). "
        f"GuardFS 로그를 확인하세요."
    )

    start = time.time()
    total_bytes = 0
    passes = 0
    rc = 0
    try:
        while time.time() - start < args.duration and (
            args.passes == 0 or passes < args.passes
        ):
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
            print(
                f"[SIM] pass {passes} 완료  누적 {total_bytes / 1024 / 1024:.1f}MB  "
                f"{time.time() - start:.1f}s"
            )
    except OSError as e:
        # ENOENT 등은 보호 차단만으로 설명되지 않으므로 결과를 단정하지 않는다.
        print(
            f"[SIM] 파일 연산 실패: {e} -> 차단 여부는 GuardFS 상태/이벤트 로그로 확인하세요."
        )
        rc = 3
    finally:
        print(
            f"[SIM] 종료: {passes} pass, 누적 {total_bytes / 1024 / 1024:.1f}MB, "
            f"{time.time() - start:.1f}s"
        )
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
