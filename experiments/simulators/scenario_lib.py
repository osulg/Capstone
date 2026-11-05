#!/usr/bin/env python3
"""
공개 침해사고 재현 시뮬레이터 공용 하네스 (GuardFS/HoldFS 탐지 검증용).

이 모듈은 실제 랜섬웨어/멀웨어가 아니다. sim_highentropy.py 가 이미 확립한
안전 불변식을 그대로 공용화한 것이며, 모든 시나리오 시뮬레이터가 아래 규칙을
공유하게 한다.

안전 불변식 (모든 시나리오가 반드시 지킨다):
  1) 대상은 "GuardFS 마운트 안에, 이 스크립트가 새로 만든 전용 workdir" 뿐이다.
     `/`, 홈 디렉터리를 대상으로 받으면 거부한다. workdir 는 매 실행마다
     시각이 붙은 새 폴더로 만든다(exist_ok=False).
  2) 이 스크립트가 만든 더미 파일만 읽고/덮어쓰고/이름 바꾸고/지운다.
     기존 사용자 파일과 실제 시스템 로그(/var/log 등)는 절대 건드리지 않는다.
  3) 암호키·C2·랜섬 수익화 로직이 없다. 복호 개념이 없으므로 결과물은
     "사고 기반 모의 재현"이다. 난수 덮어쓰기 또는 일회용 임시키 변환만 한다.
  4) 준비(평문 생성)와 공격(변조) 단계의 PID를 분리해, 준비 쓰기가 공격 PID의
     ML 프로필을 희석하지 않게 한다. 준비/공개 확인 실패·시간초과 시 공격을
     시작하지 않고 진단용 폴더를 보존한다.

시나리오에서 제외하는 범위(각 사고 문서의 "배경·범위 밖"):
  초기 접근 취약점 악용, 페이로드 전달/ingress, SSH 웜 전파, 자격 증명 탈취,
  계정 조작, C2/텔레그램 통신, Cloudflare Tunnel, 실제 ESXi/VMFS·ESXCLI·VM 전원제어.
  이들은 FUSE 파일연산 밖이거나 실제 공격 역량이므로 재현하지 않는다.
"""

from __future__ import annotations

import math
import os
import signal
import sys
import time
from typing import Callable, Sequence

# 준비 단계에서 쓰는 평문 한 줄(저엔트로피). sim_highentropy.py 와 동일 계열.
PLAINTEXT_LINE = b"This is a plain text test document for GuardFS simulation.\n"


def log(msg: str) -> None:
    """시뮬레이터 표준 출력(한 줄, 즉시 flush). GuardFS 로그와 구분되게 [SIM] 접두."""
    print(f"[SIM] {msg}", flush=True)


def err(msg: str) -> None:
    print(f"[SIM] {msg}", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# 인자 검증 헬퍼 (argparse 에서 공통으로 쓰는 양수/유한값 체크)
# --------------------------------------------------------------------------- #

def validate_positive(parser, **named: float) -> None:
    for name, value in named.items():
        if value is None:
            continue
        if not math.isfinite(value) or value <= 0:
            parser.error(f"--{name.replace('_', '-')} 은(는) 유한한 양수여야 합니다.")


def validate_non_negative(parser, **named: float) -> None:
    for name, value in named.items():
        if value is None:
            continue
        if not math.isfinite(value) or value < 0:
            parser.error(f"--{name.replace('_', '-')} 은(는) 유한한 0 이상의 값이어야 합니다.")


# --------------------------------------------------------------------------- #
# 대상 폴더 검증 및 전용 workdir 생성
# --------------------------------------------------------------------------- #

def resolve_target(target: str) -> str | None:
    """대상 경로를 정규화한다. 너무 광범위하면 None 을 반환한다."""
    resolved = os.path.realpath(os.path.expanduser(target))
    home = os.path.realpath(os.path.expanduser("~"))
    if resolved in ("/", home):
        err("대상 폴더가 너무 광범위합니다. 마운트 안의 전용 폴더를 지정하세요.")
        return None
    return resolved


def make_workdir(target: str, prefix: str) -> str:
    """대상 아래에 시각이 붙은 새 전용 폴더를 만든다. 기존 폴더는 재사용하지 않는다."""
    os.makedirs(target, exist_ok=True)
    workdir = os.path.join(target, time.strftime(f"{prefix}_%Y%m%d_%H%M%S"))
    os.makedirs(workdir, exist_ok=False)  # 이 스크립트가 새로 만든 폴더만 사용
    return workdir


# --------------------------------------------------------------------------- #
# 자식 프로세스 대기 (SIGSTOP/차단으로 멈춰도 부모는 제한시간 내 종료)
# --------------------------------------------------------------------------- #

def wait_for_child(pid: int, timeout: float, phase: str) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            return os.waitstatus_to_exitcode(status) == 0
        if time.monotonic() >= deadline:
            err(f"{phase} 시간 초과: PID={pid}")
            try:
                # 이 시뮬레이터가 만든 자식만 종료한다. pending 파일은 삭제하지 않는다.
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)
            return False
        time.sleep(0.1)


def run_in_child(fn: Callable[[], int], label: str, timeout: float) -> bool:
    """fn 을 fork 한 자식에서 실행해 PID 를 분리한다. fn 은 종료코드(int)를 반환한다."""
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid == 0:
        status = 1
        try:
            status = int(fn() or 0)
        except OSError as e:
            err(f"{label} 실패: {e}")
            status = 1
        finally:
            os._exit(status)
    log(f"{label} PID={pid}")
    return wait_for_child(pid, timeout, label)


# --------------------------------------------------------------------------- #
# 평문 더미 파일 준비 (별도 PID)
# --------------------------------------------------------------------------- #

def _plaintext_body(size: int) -> bytes:
    return (PLAINTEXT_LINE * (size // len(PLAINTEXT_LINE) + 1))[:size]


def prepare_plaintext_files(
    workdir: str,
    names: Sequence[str],
    size: int,
    timeout: float,
) -> bool:
    """이름 목록대로 평문 파일을 만든다. 준비 PID 를 공격 PID 와 분리한다."""
    body = _plaintext_body(size)

    def _make() -> int:
        for name in names:
            path = os.path.join(workdir, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(body)
        return 0

    return run_in_child(_make, "평문 준비", timeout)


def _files_ready(workdir: str, names: Sequence[str], size: int) -> bool:
    body = _plaintext_body(size)
    for name in names:
        path = os.path.join(workdir, name)
        try:
            if os.stat(path).st_size != size:
                return False
            with open(path, "rb") as handle:
                if handle.read(size + 1) != body:
                    return False
        except FileNotFoundError:
            return False
    return True


def wait_for_prepared_files(
    workdir: str,
    names: Sequence[str],
    size: int,
    timeout: float,
) -> bool:
    """공개 확인도 별도 PID 에서 수행해 공격 PID 의 ML 프로필을 보존한다."""

    def _wait() -> int:
        deadline = time.monotonic() + timeout
        while True:
            if _files_ready(workdir, names, size):
                return 0
            if time.monotonic() >= deadline:
                err("준비 파일 공개 시간 초과: commit/drop 및 상태 로그를 확인하세요.")
                return 1
            time.sleep(0.1)

    return run_in_child(_wait, "공개 확인", timeout)


# --------------------------------------------------------------------------- #
# 파일 변조 1차 요소 (시나리오들이 조합해 쓴다)
# --------------------------------------------------------------------------- #

def read_file(path: str) -> int:
    """파일 전체를 읽어 바이트 수를 반환(read-then-* 패턴의 read 단계)."""
    with open(path, "rb") as f:
        return len(f.read())


def overwrite_random(path: str, size: int, chunk: int) -> int:
    """같은 위치부터 os.urandom 난수로 덮어쓴다(고엔트로피 write)."""
    fd = os.open(path, os.O_WRONLY)
    try:
        written = 0
        while written < size:
            n = min(chunk, size - written)
            written += os.write(fd, os.urandom(n))
    finally:
        os.close(fd)
    return written


def overwrite_partial(path: str, size: int, percent: float, chunk: int) -> int:
    """
    파일 앞에서부터 percent(%) 만 난수로 덮어쓴다(부분 암호화 모사).

    나머지 뒷부분은 평문 그대로 남으므로, 헤더/매직을 보존하는 Akira 류
    부분 암호화의 '엔트로피·매직 신호 약화(헤더보존 사각지대)'를 재현한다.
    percent 는 실험 설정값이며 실제 사건의 옵션값과 일치한다는 주장이 아니다.
    """
    target = max(0, min(size, int(size * percent / 100.0)))
    fd = os.open(path, os.O_WRONLY)
    try:
        written = 0
        while written < target:
            n = min(chunk, target - written)
            written += os.write(fd, os.urandom(n))
    finally:
        os.close(fd)
    return written


def rename_to(path: str, new_path: str) -> None:
    os.rename(path, new_path)


def write_note(workdir: str, name: str, body: str) -> str:
    """디렉터리에 모의 랜섬노트(평문)를 만든다. 수익화 문구·연락처는 넣지 않는다."""
    note_path = os.path.join(workdir, name)
    with open(note_path, "w", encoding="utf-8") as f:
        f.write(body)
    return note_path


# --------------------------------------------------------------------------- #
# 정리 (차단 상태에서는 삭제도 거부될 수 있다)
# --------------------------------------------------------------------------- #

def cleanup_workdir(workdir: str, keep: bool) -> None:
    if keep:
        log(f"--keep: 작업 폴더 보존: {workdir}")
        return
    for root, dirs, files in os.walk(workdir, topdown=False):
        for name in files:
            try:
                os.unlink(os.path.join(root, name))
            except OSError as e:
                log(f"정리 실패(무시): {name}: {e}")
        for name in dirs:
            try:
                os.rmdir(os.path.join(root, name))
            except OSError:
                pass
    try:
        os.rmdir(workdir)
    except OSError:
        log(f"작업 폴더가 남아 있습니다(차단 상태일 수 있음). 수동 삭제: {workdir}")
