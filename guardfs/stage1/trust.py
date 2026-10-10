from __future__ import annotations

import os
import subprocess

import trio

TRUSTED_EXE_PREFIXES = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/")
UNTRUSTED_EXE_PREFIXES = ("/tmp/", "/home/", "/root/")
UNTRUSTED_PARENT_NAMES = ("chrome", "firefox", "thunderbird", "evolution", "outlook")

# (pid, start_time_ticks) -> is_trusted : PID 재사용 문제 방지
_trust_cache: dict[tuple, bool] = {}

# (exe_path, mtime) -> is_package_verified : 바이너리 단위 캐싱
# dpkg 조회는 비용이 크므로 같은 바이너리는 한 번만 검증
_pkg_cache: dict[tuple, bool] = {}


def _read_stat_after_comm(pid: int):
    """/proc/<pid>/stat 에서 comm(괄호) 이후 필드들을 반환."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            content = f.read()
        after_comm = content.rsplit(")", 1)[1]

        return after_comm.split()
    except Exception:
        return None


def _get_exe_path(pid: int):
    try:
        return os.path.realpath(f"/proc/{pid}/exe")
    except FileNotFoundError, PermissionError:
        return None


def _get_parent_pid(pid: int):
    fields = _read_stat_after_comm(pid)
    if not fields:
        return None
    try:
        return int(fields[1])  # ppid
    except IndexError, ValueError:
        return None


def _get_start_time(pid: int):
    fields = _read_stat_after_comm(pid)
    if not fields:
        return None
    try:
        return int(fields[19])  # starttime (clock ticks)
    except IndexError, ValueError:
        return None


def _dpkg_query_owner(exe_path: str) -> str | None:
    """dpkg -S로 해당 경로 소속 패키지명을 조회. 못 찾으면 None."""
    try:
        owner = subprocess.run(
            ["dpkg", "-S", exe_path], capture_output=True, text=True, timeout=2
        )
        if owner.returncode != 0 or not owner.stdout.strip():
            return None
        return owner.stdout.split(":")[0].strip().split(",")[0].strip()
    except subprocess.TimeoutExpired, FileNotFoundError, Exception:
        return None


def _usr_merge_alternative(path: str) -> str | None:
    pairs = (
        ("/usr/bin/", "/bin/"),
        ("/usr/sbin/", "/sbin/"),
    )

    for first, second in pairs:
        if path.startswith(first):
            return second + path[len(first) :]

        if path.startswith(second):
            return first + path[len(second) :]

    return None


def _verification_paths(path: str) -> set[str]:
    """원래 경로와 기존 usr-merge 폴백 경로를 비교 대상으로 사용"""
    paths = {os.path.normpath(path)}

    alternative = _usr_merge_alternative(path)
    if alternative is not None:
        paths.add(os.path.normpath(alternative))

    return paths | {os.path.realpath(candidate) for candidate in paths}


def _verification_report_path(line: str) -> str | None:
    """dpkg rpm 형식의 상태·선택적 conffile 표시·경로를 분리"""

    parts = line.strip().split(maxsplit=1)

    if len(parts) != 2:
        return None

    status, remainder = parts

    if status != "missing" and len(status) != 9:
        return None

    # 설정 파일은 경로 앞에 c 표시가 포함될 수 있음
    marked = remainder.split(maxsplit=1)
    if marked[0] == "c":
        if len(marked) != 2:
            return None

        remainder = marked[1]

    if not os.path.isabs(remainder):
        return None

    return remainder


def _check_package_sync(exe_path: str) -> bool:
    """
    dpkg 패키지 소속 여부 + 체크섬 무결성 검증 (블로킹, 서브프로세스 사용).
    - dpkg -S: 이 파일이 어느 apt 패키지 소속인지 확인 (소속 없으면 미검증 처리)
    - dpkg -V: 그 패키지의 파일들이 설치 당시와 다른지(변조) 확인
    - /usr/bin, /usr/sbin 경로는 dpkg 메타데이터가 옛 경로(/bin, /sbin) 기준으로
      등록된 경우가 많아(우분투의 usr-merge) 실패하면 대응 경로로 재시도한다.
    반드시 trio.to_thread.run_sync를 통해서만 호출할 것 (이벤트 루프 블로킹 방지).
    """

    try:
        # 조회 성공 여부와 무관하게 검증 보고의 대체 경로도 준비한다.
        alt_path = None
        if exe_path.startswith("/usr/bin/"):
            alt_path = "/bin/" + exe_path[len("/usr/bin/") :]
        elif exe_path.startswith("/usr/sbin/"):
            alt_path = "/sbin/" + exe_path[len("/usr/sbin/") :]
        elif exe_path.startswith("/bin/"):
            alt_path = "/usr/bin/" + exe_path[len("/bin/") :]
        elif exe_path.startswith("/sbin/"):
            alt_path = "/usr/sbin/" + exe_path[len("/sbin/") :]

        package = _dpkg_query_owner(exe_path)

        if package is None and alt_path:
            package = _dpkg_query_owner(alt_path)

        if package is None:
            return False  # 어떤 패키지에도 속하지 않음 → 서명/검증 불가로 간주

        verify = subprocess.run(
            ["dpkg", "-V", package], capture_output=True, text=True, timeout=5
        )

        if verify.returncode != 0:
            return False  # 검증 명령 실패는 신뢰로 처리하지 않는다.

        candidates = {os.path.normpath(exe_path)}

        if alt_path:
            candidates.add(os.path.normpath(alt_path))
        candidates.update(os.path.realpath(path) for path in tuple(candidates))

        for line in verify.stdout.splitlines():
            if not line.strip():
                continue

            parts = line.strip().split(maxsplit=1)

            if len(parts) != 2:
                return False  # 판별할 수 없는 보고는 비신뢰로 처리한다.

            status, reported_path = parts

            if status != "missing" and len(status) != 9:
                return False

            # 설정 파일 보고의 선택적 c 표시를 제외한다.
            marked = reported_path.split(maxsplit=1)
            if marked[0] == "c":
                if len(marked) != 2:
                    return False
                reported_path = marked[1]

            if not os.path.isabs(reported_path):
                return False

            if (
                os.path.normpath(reported_path) in candidates
                or os.path.realpath(reported_path) in candidates
            ):
                return False  # 같은 파일의 원래/대체 경로 이상 보고

        return True
    except OSError, subprocess.SubprocessError:
        return False


async def is_package_verified(exe_path: str) -> bool:
    """exe_path + mtime 단위로 캐싱된 패키지 무결성 검증 결과 반환."""
    try:
        mtime = os.path.getmtime(exe_path)
    except OSError:
        return False

    key = (exe_path, mtime)
    if key in _pkg_cache:
        return _pkg_cache[key]

    verified = await trio.to_thread.run_sync(_check_package_sync, exe_path)
    _pkg_cache[key] = verified
    return verified


async def is_trusted_pid(pid: int) -> bool:
    """
    프로세스 신뢰도 판별 (경로 + 부모 프로세스 + 패키지 무결성):
    - 시스템 경로(/usr/bin 등) 실행파일이면서, apt 패키지로 설치되고 체크섬이
      설치 당시와 일치("서명된 정상 프로세스"에 해당) → 신뢰
    - /tmp, 홈 디렉토리 실행파일 → 비신뢰
    - 부모가 브라우저/메일클라이언트 → 비신뢰
    - 판별 불가 → 비신뢰 (보수적)
    (pid, 시작시각) 조합으로 캐싱하여 PID 재사용 문제 방지.
    """
    start = _get_start_time(pid)
    cache_key = (pid, start) if start is not None else None

    if cache_key and cache_key in _trust_cache:
        return _trust_cache[cache_key]

    exe = _get_exe_path(pid)
    trusted = False

    if exe:
        if exe.startswith(UNTRUSTED_EXE_PREFIXES):
            trusted = False
        elif exe.startswith(TRUSTED_EXE_PREFIXES):
            trusted = await is_package_verified(exe)
        else:
            trusted = False  # 애매한 경로는 비신뢰

        if trusted:
            ppid = _get_parent_pid(pid)
            if ppid:
                parent_exe = _get_exe_path(ppid)
                if parent_exe and any(
                    n in parent_exe.lower() for n in UNTRUSTED_PARENT_NAMES
                ):
                    trusted = False

    if cache_key:
        _trust_cache[cache_key] = trusted
    return trusted
