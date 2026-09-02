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
        with open(f"/proc/{pid}/stat", "r") as f:
            content = f.read()
        after_comm = content.rsplit(")", 1)[1]
        return after_comm.split()
    except Exception:
        return None


def _get_exe_path(pid: int):
    try:
        return os.path.realpath(f"/proc/{pid}/exe")
    except (FileNotFoundError, PermissionError):
        return None


def _get_parent_pid(pid: int):
    fields = _read_stat_after_comm(pid)
    if not fields:
        return None
    try:
        return int(fields[1])  # ppid
    except (IndexError, ValueError):
        return None


def _get_start_time(pid: int):
    fields = _read_stat_after_comm(pid)
    if not fields:
        return None
    try:
        return int(fields[19])  # starttime (clock ticks)
    except (IndexError, ValueError):
        return None


def _dpkg_query_owner(exe_path: str) -> str | None:
    """dpkg -S로 해당 경로 소속 패키지명을 조회. 못 찾으면 None."""
    try:
        owner = subprocess.run(
            ["dpkg", "-S", exe_path],
            capture_output=True, text=True, timeout=2
        )
        if owner.returncode != 0 or not owner.stdout.strip():
            return None
        return owner.stdout.split(":")[0].strip().split(",")[0].strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return None


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
        package = _dpkg_query_owner(exe_path)

        if package is None:
            # usr-merge 대응: /usr/bin -> /bin, /usr/sbin -> /sbin 등으로 재시도
            alt_path = None
            if exe_path.startswith("/usr/bin/"):
                alt_path = "/bin/" + exe_path[len("/usr/bin/"):]
            elif exe_path.startswith("/usr/sbin/"):
                alt_path = "/sbin/" + exe_path[len("/usr/sbin/"):]
            elif exe_path.startswith("/bin/"):
                alt_path = "/usr/bin/" + exe_path[len("/bin/"):]
            elif exe_path.startswith("/sbin/"):
                alt_path = "/usr/sbin/" + exe_path[len("/sbin/"):]

            if alt_path:
                package = _dpkg_query_owner(alt_path)

        if package is None:
            return False  # 어떤 패키지에도 속하지 않음 → 서명/검증 불가로 간주

        verify = subprocess.run(
            ["dpkg", "-V", package],
            capture_output=True, text=True, timeout=5
        )
        for line in verify.stdout.splitlines():
            if exe_path in line:
                return False  # 이 파일이 변조/누락 목록에 있음

        return True
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
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
                if parent_exe and any(n in parent_exe.lower() for n in UNTRUSTED_PARENT_NAMES):
                    trusted = False

    if cache_key:
        _trust_cache[cache_key] = trusted
    return trusted
