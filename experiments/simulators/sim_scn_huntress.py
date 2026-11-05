#!/usr/bin/env python3
"""
사례 ③ Huntress 분석 Linux 침해 — 파일연산 모의 재현 (GuardFS/HoldFS 탐지 검증용).

근거: Huntress, "Untangling a Linux Incident With an OpenAI Twist (Part 2)".
하나의 시스템이 여러 공격자에게 동시에 침해된 사건. 활동을 합치지 않기 위해
정보 수집·반출의 Actor C 를 주 재현 대상으로, 로그 삭제의 Actor B 를 별도
병행 시나리오로 둔다.

이 스크립트는 실제 멀웨어가 아니다. 실제 인증 정보·시스템 로그를 쓰지 않고,
테스트용 더미 자격 파일(임의 문자열)과 더미 로그만 전용 workdir 에 만들어
다룬다. 외부 전송은 수행하지 않는다.

재현하는 구간:
  - 4.3 민감 정보 수집 (Actor C) : 더미 .ssh/.aws/.kube/.env 를 순차로 open/read.
      내용을 바꾸지 않는 '읽기 기반 기밀성 침해'. 두 변형:
        decoy(기본)   : 평범한 더미 파일로 두고 순차 읽기 → 현재 설계상 대체로 미탐
                        (쓰기·엔트로피·rename 신호가 없어 LOW 유지 가능 — 문서가
                        지적한 FUSE 사각지대)
        --honeypot    : 파일을 GuardFS 허니팟 디렉터리(<mount>/honeypot) 아래에 두고
                        읽는다 → HoneypotDetector 로 탐지/차단되는 경로를 보여준다
  - 4.5 로그 삭제 (Actor B)      : --actor-b 로 더미 로그 다수를 짧은 시간에 연속 unlink.
      stat_anomaly(1초 창 d_win ≥ 임계) → SUSPICIOUS → Stage2 로 이어지는 경로.

재현에서 제외(배경·범위 밖):
  - 4.1 페이로드 반입(Base64/wget/urllib/perl/netcat) — ingress 는 FUSE 밖
  - 4.2 지속성(cron.d/UDEV/systemd), XMRig, 에이전트 중지 — 시스템 레벨
  - 4.4 외부 반출(wget --post-file) — 실제 전송 안 함(읽기까지만; 전송은 FUSE 로
    확인 불가라는 한계를 문서화)

탐지 관점(문서 1장): 읽기 기반 탈취는 '쓰기만으로는 못 잡는 위협'이다. 하나의
프로세스가 짧은 시간에 여러 중요 경로를 연속 읽기하는 패턴, 다수 로그 연속 삭제
패턴을 특성으로 본다. 단 중요 파일 다수 읽기만으로 악성 단정은 금물(백업·관리
도구도 가능) — PID·프로세스 계보·접근 순서를 함께 본다. 읽기 기록 ≠ 유출 탐지.

테스트 방법 (Linux/Ubuntu, 터미널 두 개):
  1) 터미널 A: cd ~/Capstone && bash scripts/run_guardfs.sh   (또는 run_all.sh)
  2) 터미널 B:
       cd ~/Capstone && source venv/bin/activate
       mountpoint ~/guardfs_runtime/mount
       # Actor C (읽기 탈취, 사각지대 관찰)
       python3 experiments/simulators/sim_scn_huntress.py \
           ~/guardfs_runtime/mount/sim_huntress --keep
       # Actor C (허니팟 경유 → 탐지되는 경로)
       python3 experiments/simulators/sim_scn_huntress.py \
           ~/guardfs_runtime/mount/sim_huntress --honeypot --keep
       # Actor B (로그 연속 삭제)
       python3 experiments/simulators/sim_scn_huntress.py \
           ~/guardfs_runtime/mount/sim_huntress --actor-b --keep

확인 기준:
  - 기본(decoy) 실행: 읽기만으로는 상태가 LOW 에 머무를 수 있음을 관찰한다
    (대시보드에 격상 이벤트가 없을 수 있음 = 사각지대의 증거).
  - --honeypot: [HONEYPOT] 차단과 Stage1 HoneypotDetector 탐지가 보이는지 확인.
  - --actor-b: [SUSPICIOUS] D_win 증가 → SUSPICIOUS → Stage2 로그를 대조한다.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import scenario_lib as lib  # noqa: E402

# Actor C 가 노리는 더미 자격 파일(경로 구조만 모사, 내용은 임의 문자열).
CRED_FILES = (
    ".ssh/id_rsa",
    ".ssh/config",
    ".aws/credentials",
    ".kube/config",
    ".env",
    ".git-credentials",
)
# 실제 키가 아니라는 것을 분명히 하는 더미 본문.
DUMMY_CRED_BODY = (
    "# SIMULATION DUMMY — not a real credential.\n"
    "placeholder-token-for-guardfs-detection-test\n"
)
# Actor B 가 지우는 더미 로그 파일명(실제 /var/log 가 아니라 workdir 안).
LOG_FILES = tuple(f"fake_{n}.log" for n in (
    "auth", "kern", "syslog", "journal", "ufw", "dpkg",
    "wtmp", "btmp", "faillog", "lastlog", "cron", "boot",
))


def parse_args():
    p = argparse.ArgumentParser(description="Huntress 침해 파일연산 모의 재현")
    p.add_argument("target", help="GuardFS 마운트 안의 대상 폴더 (없으면 생성)")
    p.add_argument(
        "--honeypot",
        action="store_true",
        help="자격 더미를 <mount>/honeypot 아래에 두고 읽어 탐지 경로를 보여준다",
    )
    p.add_argument(
        "--actor-b",
        action="store_true",
        help="Actor C(읽기) 대신 Actor B(로그 연속 삭제) 시나리오를 실행",
    )
    p.add_argument(
        "--log-files", type=int, default=len(LOG_FILES),
        help="Actor B 가 만들고 삭제할 더미 로그 개수",
    )
    p.add_argument(
        "--read-passes", type=int, default=1,
        help="Actor C 가 자격 파일 전체를 읽는 반복 횟수",
    )
    p.add_argument(
        "--delay", type=float, default=0.1,
        help="연산 간 대기(초). Actor B 는 짧게 둬야 1초 창 삭제 버스트가 된다",
    )
    p.add_argument("--keep", action="store_true", help="종료 후 테스트 파일 보존")
    p.add_argument(
        "--prepare-timeout", type=float, default=30.0,
        help="준비/공개 확인 단계별 최대 대기 시간(초)",
    )
    args = p.parse_args()
    if args.log_files <= 0 or args.read_passes <= 0:
        p.error("--log-files, --read-passes 는 양수여야 합니다.")
    lib.validate_positive(p, prepare_timeout=args.prepare_timeout)
    lib.validate_non_negative(p, delay=args.delay)
    return args


def _honeypot_root(target: str) -> str:
    """
    <mount>/honeypot 경로를 target 으로부터 역산한다.

    GuardFS 는 honeypot 디렉터리를 마운트 루트 바로 아래(<mount>/honeypot)에 둔다
    (paths.get_honeypot_dir). target 이 그 마운트 안의 하위 폴더이므로, 상위로
    올라가며 honeypot 를 찾는다. 못 찾으면 target 바로 위를 마운트로 가정한다.
    """
    cur = target
    for _ in range(8):
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        candidate = os.path.join(parent, "honeypot")
        if os.path.isdir(candidate):
            return candidate
        cur = parent
    # fallback: target 의 부모를 마운트로 가정
    return os.path.join(os.path.dirname(target), "honeypot")


def run_actor_c_honeypot(target: str) -> int:
    """
    허니팟 경유 탐지 경로 재현.

    허니팟 미끼 파일은 관리자/GuardFS 가 미리 심어 두는 것이지, 공격자가
    마운트를 통해 만드는 것이 아니다(허니팟 안 create/write 는 그 자체로
    차단·탐지 대상이라 준비가 오히려 막힌다). 따라서 여기서는 파일을 만들지
    않고, 허니팟 아래 자격 파일명을 '읽으려는 접근'만 시도한다. 접근 시도
    자체가 HoneypotDetector 를 울린다(파일이 없어도 lookup/open 에서 탐지).
    """
    hp = _honeypot_root(target)
    lib.log(f"[허니팟 모드] 허니팟 경로 추정: {hp}")
    lib.log(
        "허니팟 미끼는 GuardFS/관리자가 미리 심어 둔다고 전제한다. "
        "여기서는 미끼 경로에 대한 '읽기 접근 시도'만 한다(생성하지 않음)."
    )
    lib.log(
        f"공격 역할 PID={os.getpid()} — 허니팟 자격 경로 접근 시도. "
        f"GuardFS 로그/대시보드에서 [HONEYPOT] 차단과 HoneypotDetector 탐지를 확인하세요."
    )
    decoys = ("id_rsa", "credentials", "config", ".env", "api_token.txt")
    rc = 0
    for name in decoys:
        path = os.path.join(hp, name)
        try:
            with open(path, "rb") as f:
                f.read()
            lib.log(f"허니팟 접근 성공(차단 안 됨?): {name}")
        except OSError as e:
            # 차단(EACCES/EPERM) 또는 미끼 미배치(ENOENT) 모두 접근 시도는 기록된다.
            lib.log(f"허니팟 접근 시도 {name}: {e}")
        time.sleep(0.1)
    return rc


def run_actor_c(target: str, args) -> int:
    """읽기 기반 민감정보 수집(기밀성 침해) 재현."""
    if args.honeypot:
        return run_actor_c_honeypot(target)

    workdir = lib.make_workdir(target, "huntress_actorC")
    lib.log(f"작업 폴더: {workdir}")

    # 더미 자격 파일 준비(작은 평문). 준비 PID 는 공격 PID 와 분리.
    size = max(len(lib.PLAINTEXT_LINE), 256)
    if not lib.prepare_plaintext_files(workdir, CRED_FILES, size, args.prepare_timeout):
        lib.log(f"더미 자격 준비 실패. 미시작; 폴더 보존: {workdir}")
        return 1
    if not lib.wait_for_prepared_files(workdir, CRED_FILES, size, args.prepare_timeout):
        lib.log(f"준비 확인 실패. 미시작; 폴더 보존: {workdir}")
        return 1

    lib.log(
        f"공격 역할 PID={os.getpid()} — 자격 더미 {len(CRED_FILES)}개 순차 읽기 "
        f"x{args.read_passes}pass. GuardFS 로그/대시보드를 확인하세요."
    )

    rc = 0
    try:
        for _ in range(args.read_passes):
            for name in CRED_FILES:
                path = os.path.join(workdir, name)
                try:
                    n = lib.read_file(path)
                    lib.log(f"read {name} ({n}B)")
                except OSError as e:
                    lib.log(f"read 실패 {name}: {e}")
                    rc = 3
                if args.delay:
                    time.sleep(args.delay)
        # 4.4 외부 반출은 수행하지 않는다(실제 전송 없음).
        lib.log("외부 반출(wget --post-file)은 재현하지 않음 — FUSE 로 확인 불가 구간")
    finally:
        lib.cleanup_workdir(workdir, args.keep)
    if rc == 0:
        lib.log(
            "참고: 읽기만으로 상태가 LOW 에 머물렀다면, 이는 '읽기 기반 탈취'의 "
            "FUSE 탐지 사각지대를 보여주는 예상된 결과다(문서 6장 한계)."
        )
    return rc


def run_actor_b(target: str, args) -> int:
    """다수 로그 연속 삭제(흔적 제거) 재현."""
    workdir = lib.make_workdir(target, "huntress_actorB")
    lib.log(f"작업 폴더: {workdir}")
    names = list(LOG_FILES[: args.log_files]) if args.log_files <= len(LOG_FILES) else [
        f"fake_{i}.log" for i in range(args.log_files)
    ]
    size = max(len(lib.PLAINTEXT_LINE), 256)
    if not lib.prepare_plaintext_files(workdir, names, size, args.prepare_timeout):
        lib.log(f"더미 로그 준비 실패. 미시작; 폴더 보존: {workdir}")
        return 1
    if not lib.wait_for_prepared_files(workdir, names, size, args.prepare_timeout):
        lib.log(f"준비 확인 실패. 미시작; 폴더 보존: {workdir}")
        return 1

    lib.log(
        f"공격 역할 PID={os.getpid()} — 더미 로그 {len(names)}개 연속 삭제(버스트). "
        f"GuardFS 로그/대시보드에서 [SUSPICIOUS] D_win 증가를 확인하세요."
    )
    rc = 0
    deleted = 0
    try:
        for name in names:
            path = os.path.join(workdir, name)
            try:
                os.unlink(path)
                deleted += 1
            except OSError as e:
                lib.log(f"unlink 실패 {name}: {e} (차단일 수 있음)")
                rc = 3
            if args.delay:
                time.sleep(args.delay)
        lib.log(f"연속 삭제 완료: {deleted}개")
    finally:
        lib.cleanup_workdir(workdir, args.keep)
    return rc


def main() -> int:
    args = parse_args()
    target = lib.resolve_target(args.target)
    if target is None:
        return 2
    if args.actor_b:
        return run_actor_b(target, args)
    return run_actor_c(target, args)


if __name__ == "__main__":
    sys.exit(main())
