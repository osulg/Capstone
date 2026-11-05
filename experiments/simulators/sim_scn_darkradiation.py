#!/usr/bin/env python3
"""
사례 ② DarkRadiation 랜섬웨어 — 파일연산 모의 재현 (GuardFS/HoldFS 탐지 검증용).

근거: Trend Micro, "Bash Ransomware DarkRadiation" (2021-06); SentinelOne 병행 분석.

이 스크립트는 실제 랜섬웨어가 아니다. C2·텔레그램·웜·계정 조작이 없고, 암호키는
일회용 난수로 그때그때 버린다(수익화·복호 개념 없음). 이 스크립트가 만든 전용
workdir 의 더미 파일만 변조한다.

재현하는 구간 (문서 3.4, + 신뢰 엔진 사용):
  - 3.4 파일 암호화 : 더미 파일을 open/read → AES-CBC 로 암호화해 덮어씀
                      → 방사능 기호(U+2622) 확장자로 rename
  - 핵심 차별점      : '쓰기 주체를 신뢰 시스템 도구로' 둔다.
      --engine openssl  : 시스템 /usr/bin/openssl(패키지 검증되는 신뢰 경로)로 암호화.
                          문서의 "시스템 openssl AES-CBC" 와 동일. 단, 파일당
                          openssl 프로세스가 새로 뜨고 즉시 종료되는 one-shot PID 다.
      --engine inprocess: 한 프로세스가 cryptography 로 AES 를 수행(긴 수명 단일 PID).
                          Stage2 가 PID 단위 행동 프로필을 쌓을 수 있는 형태.

재현에서 제외(배경·범위 밖):
  - 3.1 bash SSH 웜 전파(downloader.sh/sshpass) — "자격·셸 확보" 전제로 대체
  - 3.2 openssl/yum 설치 전제 — 시스템에 openssl 이 있으면 그대로 사용
  - 3.3 모니터링·계정 장악(who/shadow/ferrum/docker) — 시스템 레벨, FUSE 밖

탐지 관점(문서 1장): 쓰기 주체가 신뢰라 Stage 1 경량 게이트(비신뢰 → 선제 MEDIUM)가
설계상 약해지고, 행위를 보는 Stage 2 동적 ML(dyn 단독 격상)이 유일한 탐지 주체가 된다.
검증 시 (a) 재평가 지연 동안 몇 개가 변경되는지(탐지 ≠ 완전 차단), (b) 정상 작업
오탐을 함께 본다. openssl 사용 사실만으로 우회를 단정하지 않는다.

주의(신뢰 분류는 실행 방식에 달려 있다):
  GuardFS 의 신뢰 판정은 프로세스의 exe 경로(/usr/bin 등 + dpkg 검증)를 본다.
  --engine openssl 은 쓰기 주체가 실제 /usr/bin/openssl 이라 신뢰로 분류된다.
  --engine inprocess 는 이 스크립트를 '어떻게 띄웠는지'에 따라 달라진다. 신뢰
  시연이 목적이면 openssl 엔진을, 비교(비신뢰 스크립트)가 목적이면 inprocess 를
  venv/홈 경로에서 실행한다.

테스트 방법 (Linux/Ubuntu, 터미널 두 개):
  1) 터미널 A: cd ~/Capstone && bash scripts/run_guardfs.sh   (또는 run_all.sh)
  2) 터미널 B:
       cd ~/Capstone && source venv/bin/activate
       mountpoint ~/guardfs_runtime/mount
       python3 experiments/simulators/sim_scn_darkradiation.py \
           ~/guardfs_runtime/mount/sim_darkradiation --engine openssl --keep

확인 기준:
  - 신뢰 엔진이 고엔트로피 write 를 수행하는 동안의 상태 전이(SUSPICIOUS → Stage2
    재평가 → MEDIUM/HIGH)를 대조한다. MEDIUM 재평가 지연 동안 반영된(=손실된)
    파일 수를 센다. HIGH 도달 시 이후 write/rename 차단을 확인한다.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import scenario_lib as lib  # noqa: E402

RADIATION = "☢"  # ☢ : DarkRadiation 이 암호화 파일에 붙이는 기호
OPENSSL = "/usr/bin/openssl"


def parse_args():
    p = argparse.ArgumentParser(description="DarkRadiation 파일연산 모의 재현")
    p.add_argument("target", help="GuardFS 마운트 안의 대상 폴더 (없으면 생성)")
    p.add_argument(
        "--engine",
        choices=("inprocess", "openssl"),
        default="inprocess",
        help="암호화 주체. openssl=시스템 신뢰 바이너리, inprocess=단일 프로세스",
    )
    p.add_argument("--files", type=int, default=10, help="테스트 파일 개수")
    p.add_argument("--size-kb", type=int, default=64, help="파일당 크기(KB)")
    p.add_argument(
        "--delay",
        type=float,
        default=0.15,
        help="파일 간 대기(초). Stage2 재평가(1초 주기)가 개입할 시간을 준다",
    )
    p.add_argument("--duration", type=float, default=30.0, help="최대 반복 시간(초)")
    p.add_argument("--keep", action="store_true", help="종료 후 테스트 파일 보존")
    p.add_argument(
        "--prepare-timeout",
        type=float,
        default=30.0,
        help="준비/공개 확인 단계별 최대 대기 시간(초)",
    )
    args = p.parse_args()
    if args.files <= 0 or args.size_kb <= 0:
        p.error("--files, --size-kb 는 양수여야 합니다.")
    lib.validate_positive(
        p, prepare_timeout=args.prepare_timeout, duration=args.duration
    )
    lib.validate_non_negative(p, delay=args.delay)
    if args.engine == "openssl" and not os.path.exists(OPENSSL):
        p.error(f"{OPENSSL} 가 없습니다. --engine inprocess 를 사용하세요.")
    return args


def _aes_encrypt_inprocess(path: str) -> int:
    """cryptography 로 AES-256-CBC 암호화해 같은 파일을 덮어쓴다(일회용 키)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key = os.urandom(32)  # 일회용. 저장/전송하지 않는다(수익화·복호 없음).
    iv = os.urandom(16)
    with open(path, "rb") as f:
        data = f.read()
    pad = 16 - (len(data) % 16)
    data += bytes([pad] * pad)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    cipher = enc.update(data) + enc.finalize()
    with open(path, "wb") as f:
        f.write(iv + cipher)
    return len(cipher)


def _aes_encrypt_openssl(path: str) -> int:
    """시스템 openssl(신뢰 경로)로 암호화. openssl 이 read+write 를 수행한다."""
    tmp = path + ".tmp"
    # 일회용 패스프레이즈. 저장/전송하지 않는다.
    passphrase = os.urandom(16).hex()
    # openssl 프로세스가 입력을 읽고(read) 출력을 쓴다(write). 둘 다 마운트 위.
    subprocess.run(
        [
            OPENSSL, "enc", "-aes-256-cbc", "-pbkdf2",
            "-in", path, "-out", tmp, "-pass", f"pass:{passphrase}",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    size = os.path.getsize(tmp)
    # 원본을 암호문으로 교체(원본 unlink 는 이 스크립트가 수행).
    os.replace(tmp, path)
    return size


def main() -> int:
    args = parse_args()

    target = lib.resolve_target(args.target)
    if target is None:
        return 2

    workdir = lib.make_workdir(target, "darkradiation")
    size = args.size_kb * 1024
    names = [f"data_{i:03d}.txt" for i in range(args.files)]

    lib.log(f"작업 폴더: {workdir}")
    lib.log(f"[3.1~3.3 전제] 준비: 평문 {args.files}개 x {args.size_kb}KB (자식 PID)")
    if not lib.prepare_plaintext_files(workdir, names, size, args.prepare_timeout):
        lib.log(f"평문 준비 실패. 공격 미시작; 진단용 폴더 보존: {workdir}")
        return 1
    if not lib.wait_for_prepared_files(workdir, names, size, args.prepare_timeout):
        lib.log(f"준비 확인 실패. 공격 미시작; 진단용 폴더 보존: {workdir}")
        return 1

    encrypt = _aes_encrypt_openssl if args.engine == "openssl" else _aes_encrypt_inprocess
    engine_desc = (
        f"{OPENSSL} (신뢰 시스템 바이너리, 파일당 one-shot PID)"
        if args.engine == "openssl"
        else "cryptography AES (단일 프로세스)"
    )
    lib.log(f"준비 완료. 암호화 엔진: {engine_desc}")
    lib.log(
        f"공격 역할 PID={os.getpid()} (duration={args.duration}s). "
        f"GuardFS 로그/대시보드를 확인하세요."
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
            # 3.4 open/read → AES 암호화(고엔트로피 write) → ☢ rename
            lib.read_file(path)
            total += encrypt(path)
            new_path = path + RADIATION
            lib.rename_to(path, new_path)
            paths[i] = new_path
            if args.delay:
                time.sleep(args.delay)
    except (OSError, subprocess.SubprocessError) as e:
        lib.log(f"파일 연산 실패: {e} → 차단 여부는 GuardFS 상태/이벤트 로그로 확인")
        rc = 3
    finally:
        lib.log(
            f"종료: {total / 1024 / 1024:.1f}MB 암호화, {time.time() - start:.1f}s"
        )
        lib.cleanup_workdir(workdir, args.keep)
    return rc


if __name__ == "__main__":
    sys.exit(main())
