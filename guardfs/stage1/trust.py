from __future__ import annotations

import os
import re
import subprocess

import trio

from guardfs.common.config import INTERPRETER_BASENAMES
from guardfs.common.config import TRUSTED_EXE_PREFIXES as TRUSTED_SCRIPT_PREFIXES

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


# ---------------------------------------------------------------------------
# 인터프리터가 실제로 실행하는 대상 (스크립트·모듈·인라인 코드)
#
# /usr/bin/python3, /usr/bin/bash 같은 인터프리터는 실행 파일만 보면 신뢰 경로지만,
# 실제로 도는 코드는 인자로 받은 스크립트다. 실행 파일만 보면 홈 디렉터리의 임의
# 스크립트도 신뢰로 분류된다. passthrough.is_trusted_process(SUSPICIOUS 처리)와
# is_trusted_pid(첫 쓰기 전 선제 MEDIUM)가 같은 기준을 쓰도록 여기서 한 번만 해석한다.
# ---------------------------------------------------------------------------

# 인터프리터 종류별 인자 규칙
#   inline : 다음 인자가 코드 문자열 (검증할 수 없으므로 비신뢰)
#   module : 다음 인자가 모듈 이름 (python -m)
#   script : 다음 인자가 스크립트 경로 (php -f)
#   takes  : 값을 하나 받는 옵션 (다음 인자는 대상이 아님)
_ARG_RULES = {
    "python": {"inline": {"-c"}, "module": {"-m"}, "script": set(), "takes": {"-W", "-X", "-Q"}},
    "perl": {"inline": {"-e", "-E"}, "module": set(), "script": set(), "takes": {"-I", "-M", "-m", "-x"}},
    "ruby": {"inline": {"-e"}, "module": set(), "script": set(), "takes": {"-I", "-r", "-C", "-E"}},
    "node": {"inline": {"-e", "--eval", "-p", "--print"}, "module": set(), "script": set(),
             "takes": {"-r", "--require", "--import", "--loader"}},
    "php": {"inline": {"-r"}, "module": set(), "script": {"-f"}, "takes": {"-c", "-d", "-z"}},
    "shell": {"inline": {"-c"}, "module": set(), "script": set(), "takes": {"-o", "+o", "-O", "+O"}},
}
_SHELLS = {"bash", "sh", "dash", "zsh"}
# 표준입력에서 코드를 읽는 인자 (대화형 셸·REPL과 같이 취급)
_STDIN_ARGS = {"-", "-s", "-i"}


def _interpreter_family(exe_path: str) -> str | None:
    """실행 파일이 인터프리터면 종류(python·perl·…·shell), 아니면 None."""
    basename = re.sub(r"[\d.]+$", "", os.path.basename(exe_path or ""))
    if basename not in INTERPRETER_BASENAMES and basename + "3" not in INTERPRETER_BASENAMES:
        return None
    if basename in _SHELLS:
        return "shell"
    if basename == "nodejs":
        return "node"
    return basename if basename in _ARG_RULES else None


def _resolve_module(module: str, cwd: str | None) -> str | None:
    """python -m 모듈을 실행 위치(cwd) 기준 파일로 찾는다. 찾지 못하면 None."""
    if not cwd or not re.fullmatch(r"[A-Za-z_][\w.]*", module):
        return None
    base = os.path.join(cwd, *module.split("."))
    for candidate in (base + ".py", os.path.join(base, "__main__.py"), os.path.join(base, "__init__.py")):
        if os.path.isfile(candidate):
            return os.path.realpath(candidate)
    return None


def classify_interpreter_args(exe_path: str, args: list[str], cwd: str | None) -> tuple[str, str]:
    """
    인터프리터가 실행하는 대상을 분류한다. (args 는 cmdline 에서 argv[0] 을 뺀 인자)

    반환 (kind, path)
      not_interpreter : 인터프리터가 아님 (path = 실행 파일)
      script          : 스크립트·모듈 파일 (path = 대상 파일의 절대 경로)
      stdin           : 대상 인자 없음 (대화형 셸, REPL, 표준입력)
      inline          : -c/-e 같은 인라인 코드
      unknown         : 대상이 있지만 파일로 확인할 수 없음 (찾을 수 없는 모듈 등)
    """
    family = _interpreter_family(exe_path)
    if family is None:
        return "not_interpreter", exe_path
    rules = _ARG_RULES[family]

    def absolute(path: str) -> str:
        if not os.path.isabs(path):
            if not cwd:
                return ""
            path = os.path.join(cwd, path)
        return os.path.realpath(path)

    i = 0
    while i < len(args):
        arg = args[i]
        nxt = args[i + 1] if i + 1 < len(args) else None
        if arg in rules["inline"]:
            return "inline", ""
        if arg in rules["module"]:
            found = _resolve_module(nxt or "", cwd)
            return ("script", found) if found else ("unknown", "")
        if arg in rules["script"]:
            target = absolute(nxt) if nxt else ""
            return ("script", target) if target else ("unknown", "")
        if arg in _STDIN_ARGS:
            return "stdin", ""
        if arg == "--":
            return ("script", absolute(nxt) or "") if nxt else ("stdin", "")
        if arg in rules["takes"]:
            i += 2
            continue
        if arg.startswith("-") or arg.startswith("+"):
            i += 1
            continue
        target = absolute(arg)
        return ("script", target) if target else ("unknown", "")
    return "stdin", ""


def interpreter_target(pid: int, exe_path: str | None = None) -> tuple[str, str]:
    """/proc 에서 실행 파일·인자·실행 위치를 읽어 classify_interpreter_args 로 분류한다."""
    if exe_path is None:
        try:
            exe_path = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            return "unknown", ""
    if _interpreter_family(exe_path) is None:
        return "not_interpreter", exe_path
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read()
    except OSError:
        return "unknown", ""
    try:
        cwd = os.readlink(f"/proc/{pid}/cwd")
    except OSError:
        cwd = None
    args = [a.decode("utf-8", "surrogateescape") for a in raw.split(b"\x00") if a]
    return classify_interpreter_args(exe_path, args[1:], cwd)


def is_trusted_script_path(path: str) -> bool:
    """스크립트 경로가 시스템 신뢰 경로(config.TRUSTED_EXE_PREFIXES) 안에 있는지."""
    if not path or path.startswith(UNTRUSTED_EXE_PREFIXES):
        return False
    return any(path == p or path.startswith(p.rstrip("/") + "/") for p in TRUSTED_SCRIPT_PREFIXES)


def _dpkg_query_owner(exe_path: str) -> str | None:
    """dpkg -S로 해당 경로 소속 패키지명을 조회. 못 찾으면 None."""
    try:
        owner = subprocess.run(
            ["dpkg", "-S", exe_path], capture_output=True, text=True, timeout=2
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
    except (OSError, subprocess.SubprocessError):
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
    - 인터프리터(python·bash 등)면 실제로 실행하는 스크립트·모듈도 시스템
      신뢰 경로 안이어야 신뢰. 인라인 코드(-c/-e)나 찾을 수 없는 모듈은 비신뢰.
      대상 인자가 없는 대화형 셸·REPL·표준입력은 실행 파일 기준을 그대로 쓴다.
      (passthrough.is_trusted_process 와 같은 대상 해석: interpreter_target)
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

        if trusted:
            kind, target = interpreter_target(pid, exe)
            if kind == "script":
                trusted = is_trusted_script_path(target)
            elif kind in ("inline", "unknown"):
                trusted = False

    if cache_key:
        _trust_cache[cache_key] = trusted
    return trusted
