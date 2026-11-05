#!/usr/bin/env python3
"""
사례 ④ Akira 랜섬웨어 (Linux/VMware ESXi) — 파일연산 모의 재현 (GuardFS/HoldFS 검증용).

근거(증거 수준 분리):
  ⒜ Recon InfoSec "Emergence of Akira Ransomware Group"(2023-05, 실제 IR)
  ⒝ Palo Alto Unit 42 "Howling Scorpius"(샘플 분석) — 변종 실행 옵션·암호화
  ⒞ FBI·CISA AA24-109A(종합 권고)
  ⒟ 안랩 Akira(한국어) — 계열 TTP 교차검증

이 스크립트는 실제 랜섬웨어가 아니다. 실제 ESXi/VMFS·바이너리·VM 전원제어가 없고,
이 스크립트가 만든 전용 workdir 의 '더미 VM 파일'(실제 디스크 아님)만 부분적으로
난수로 덮어쓴다. 암호키·복호·수익화 로직이 없다.

재현하는 구간 (문서 5.6 + Unit42 변종 옵션의 파일 측면):
  - 더미 .vmdk/.vmx/.vmsd/.vmsn 파일을 open/read
  - 파일 앞부분 일부 비율(--encryption-percent)만 난수로 덮어씀(부분 암호화 모사)
    → 나머지는 평문 → 헤더/매직 보존 → 엔트로피·매직 신호 약화(헤더보존 사각지대)
  - .akiranew 로 rename, akiranew.txt 모의 노트 생성

재현에서 제외(배경·범위 밖):
  - 5.1 Cloudflare Tunnel(cloudflared 위장), 5.2 Netscan, 5.3 Mimikatz/DonPAPI,
    5.4 RDP/wmiexec·계정 생성, 5.5 net use·7-Zip/WinRAR 수집·압축
  - 5.6 실제 ESXi SSH 접속·VMFS 암호화, ESXCLI(syslog/coredump), vim-cmd VM 전원제어
  이들은 실제 공격 역량이거나 FUSE 밖이다. --encryption-percent 는 "실험 설정값"이며
  실제 사건 옵션값(-n)과 일치한다는 주장이 아니다.

범위 한계(문서 5.7): GuardFS 가 ESXi VMFS 를 직접 보호하는 것이 아니라, VM 파일
변경 특성을 일반 Linux FUSE 에서 유사 파일 연산으로 모사해 검증하는 것이다.

탐지 관점(문서 1장): 부분 암호화는 파일 대부분이 평문으로 남아 헤더 기반 엔트로피·
매직 신호가 약해지는 탐지 한계를 드러낸다. GuardFS 에서 EntropyDetector 는 파일
앞 ENTROPY_HEADER_SIZE(256B) 를 보므로, 앞부분만 덮어쓰면 오히려 걸리고 뒷부분만
덮어쓰면 놓칠 수 있다 — 이 비대칭을 --offset 로 확인한다. rename(.akiranew)·반복
쓰기·ML 종합이 보조 신호가 된다.

테스트 방법 (Linux/Ubuntu, 터미널 두 개):
  1) 터미널 A: cd ~/Capstone && bash scripts/run_guardfs.sh   (또는 run_all.sh)
  2) 터미널 B:
       cd ~/Capstone && source venv/bin/activate
       mountpoint ~/guardfs_runtime/mount
       python3 experiments/simulators/sim_scn_akira.py \
           ~/guardfs_runtime/mount/sim_akira --encryption-percent 20 --keep

확인 기준:
  - 부분 암호화 비율(--encryption-percent)과 쓰기 위치(--offset head/tail)에 따라
    EntropyDetector 탐지 여부가 달라지는지 대조한다. .akiranew rename 과 ML 재평가
    로그를 함께 본다. '탐지 한계(헤더보존)'가 예상된 결과임을 기록한다.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import scenario_lib as lib  # noqa: E402

# Akira_v2 --vmonly 대상 확장자(파일 측면만 모사; 실제 VM 디스크 아님).
VM_EXTS = (".vmdk", ".vmx", ".vmsd", ".vmsn", ".vmem")
NEW_EXT = ".akiranew"
NOTE_NAME = "akiranew.txt"
NOTE_BODY = (
    "[SIMULATION] GuardFS detection test artifact.\n"
    "No real encryption, key, VM, or contact information is involved.\n"
)


def parse_args():
    p = argparse.ArgumentParser(description="Akira(Linux/ESXi) 파일연산 모의 재현")
    p.add_argument("target", help="GuardFS 마운트 안의 대상 폴더 (없으면 생성)")
    p.add_argument("--files", type=int, default=8, help="더미 VM 파일 개수")
    # 기본 64KB: VM 확장자는 EXTENSION_GROUPS 어디에도 없어 UNKNOWN 그룹(버퍼 상한
    # 2MB)으로 분류된다. 준비 단계의 평문 쓰기가 전부 MEDIUM 버퍼에 쌓이므로,
    # files*size 가 2MB 를 넘으면 공격 시작 전에 준비 PID 가 buffer_limit_exceeded
    # 로 HIGH 격상돼 준비가 막힌다(8*256KB=2MB 에서 실측 확인). 8*64KB=512KB 로 여유.
    p.add_argument("--size-kb", type=int, default=64, help="파일당 크기(KB)")
    p.add_argument(
        "--encryption-percent",
        type=float,
        default=20.0,
        help="파일에서 난수로 덮어쓸 비율(%%). 부분 암호화 모사(실험 설정값)",
    )
    p.add_argument(
        "--offset",
        choices=("head", "tail"),
        default="head",
        help="덮어쓸 위치. head=앞부분(헤더 포함), tail=뒷부분(헤더 보존)",
    )
    p.add_argument("--chunk-kb", type=int, default=16, help="한 번에 쓰는 난수 크기(KB)")
    p.add_argument("--delay", type=float, default=0.15, help="파일 간 대기(초)")
    p.add_argument("--duration", type=float, default=30.0, help="최대 반복 시간(초)")
    p.add_argument("--keep", action="store_true", help="종료 후 테스트 파일 보존")
    p.add_argument(
        "--prepare-timeout", type=float, default=30.0,
        help="준비/공개 확인 단계별 최대 대기 시간(초)",
    )
    args = p.parse_args()
    if args.files <= 0 or args.size_kb <= 0 or args.chunk_kb <= 0:
        p.error("--files, --size-kb, --chunk-kb 는 양수여야 합니다.")
    if not (0 < args.encryption_percent <= 100):
        p.error("--encryption-percent 는 0 초과 100 이하여야 합니다.")
    lib.validate_positive(
        p, prepare_timeout=args.prepare_timeout, duration=args.duration
    )
    lib.validate_non_negative(p, delay=args.delay)
    return args


def overwrite_partial_at(path: str, size: int, percent: float, chunk: int, where: str) -> int:
    """percent(%)만 난수로 덮어쓴다. where=head 면 앞에서, tail 이면 뒤에서."""
    target = max(1, min(size, int(size * percent / 100.0)))
    start = 0 if where == "head" else max(0, size - target)
    fd = os.open(path, os.O_WRONLY)
    try:
        os.lseek(fd, start, os.SEEK_SET)
        written = 0
        while written < target:
            n = min(chunk, target - written)
            written += os.write(fd, os.urandom(n))
    finally:
        os.close(fd)
    return written


def main() -> int:
    args = parse_args()
    target = lib.resolve_target(args.target)
    if target is None:
        return 2

    workdir = lib.make_workdir(target, "akira")
    size = args.size_kb * 1024
    chunk = args.chunk_kb * 1024
    # 더미 VM 파일(확장자를 번갈아 부여).
    names = [f"vm_{i:03d}{VM_EXTS[i % len(VM_EXTS)]}" for i in range(args.files)]

    lib.log(f"작업 폴더: {workdir}")
    lib.log(f"[5.1~5.6 전제] 준비: 더미 VM 파일 {args.files}개 x {args.size_kb}KB (자식 PID)")
    if not lib.prepare_plaintext_files(workdir, names, size, args.prepare_timeout):
        lib.log(f"준비 실패. 공격 미시작; 진단용 폴더 보존: {workdir}")
        return 1
    if not lib.wait_for_prepared_files(workdir, names, size, args.prepare_timeout):
        lib.log(f"준비 확인 실패. 공격 미시작; 진단용 폴더 보존: {workdir}")
        return 1

    lib.log(
        f"준비 완료. 부분 암호화 {args.encryption_percent:.0f}% ({args.offset}). "
        f"공격 역할 PID={os.getpid()} (duration={args.duration}s)."
    )
    paths = [os.path.join(workdir, n) for n in names]
    start = time.time()
    total = 0
    rc = 0
    try:
        for i, path in enumerate(paths):
            if time.time() - start >= args.duration:
                lib.log("duration 초과 → 중단")
                break
            lib.read_file(path)
            total += overwrite_partial_at(
                path, size, args.encryption_percent, chunk, args.offset
            )
            new_path = path + NEW_EXT
            lib.rename_to(path, new_path)
            paths[i] = new_path
            if args.delay:
                time.sleep(args.delay)
        lib.write_note(workdir, NOTE_NAME, NOTE_BODY)
        lib.log(f"모의 노트 생성: {NOTE_NAME}")
    except OSError as e:
        lib.log(f"파일 연산 실패: {e} → 차단 여부는 GuardFS 상태/이벤트 로그로 확인")
        rc = 3
    finally:
        lib.log(
            f"종료: {total / 1024 / 1024:.1f}MB 부분 덮어씀, {time.time() - start:.1f}s"
        )
        lib.cleanup_workdir(workdir, args.keep)
    if rc == 0 and args.offset == "tail":
        lib.log(
            "참고: tail 부분 암호화로 EntropyDetector(헤더 256B)가 놓쳤다면 "
            "이는 부분 암호화의 헤더보존 사각지대를 보여주는 예상된 결과다."
        )
    return rc


if __name__ == "__main__":
    sys.exit(main())
