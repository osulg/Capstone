"""
시스템 현황 탭용 상태 확인 (읽기 전용)

- HoldFS 프로세스: /proc/<pid>/cmdline 에서 HoldFS 실행 파일 이름을 찾는다.
- 마운트: /proc/mounts 에 HoldFS 마운트 경로가 fuse 로 걸려 있는지 본다.
- 로그 수집 agent: /proc 에서 dashboard/agent.py 프로세스를 찾는다.

/proc 가 없는 환경(Windows 등)에서는 모두 '꺼짐'으로 나온다.
대시보드 서버가 HoldFS와 같은 머신(VM)에서 돌 때만 의미가 있다.
"""

from __future__ import annotations

import os

MOUNT_DIR = os.path.expanduser(os.environ.get("DASH_MOUNT_DIR", "~/guardfs_runtime/mount"))

# 프로세스 cmdline 에 들어 있으면 해당 프로세스로 본다
HOLDFS_MARKERS = ("guardfs/fuse_fs/passthrough.py", "guardfs.fuse_fs.passthrough",
                  "guardfs/main.py", "guardfs.main")
AGENT_MARKERS = ("dashboard/agent.py", "dashboard.agent")


def _find_process(markers: tuple[str, ...]) -> int | None:
    """cmdline 에 markers 중 하나가 들어 있는 첫 프로세스의 PID."""
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return None
    me = os.getpid()
    for p in pids:
        if int(p) == me:
            continue
        try:
            with open(f"/proc/{p}/cmdline", "rb") as f:
                cmd = f.read().replace(b"\0", b" ").decode("utf-8", "replace")
        except OSError:
            continue  # 그 사이 종료됐거나 권한 없음
        if any(m in cmd for m in markers):
            return int(p)
    return None


def _is_mounted(path: str, mounts_file: str = "/proc/mounts") -> bool:
    real = os.path.realpath(path)
    try:
        with open(mounts_file, encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 3:
                    continue
                # /proc/mounts 는 공백을 \040 으로 적는다
                mnt = parts[1].replace("\\040", " ")
                if mnt == real and parts[2].startswith("fuse"):
                    return True
    except OSError:
        pass
    return False


def status() -> dict:
    holdfs_pid = _find_process(HOLDFS_MARKERS)
    agent_pid = _find_process(AGENT_MARKERS)
    mounted = _is_mounted(MOUNT_DIR)
    return {
        "holdfs": {"running": holdfs_pid is not None, "pid": holdfs_pid},
        "mount": {"mounted": mounted, "path": MOUNT_DIR},
        "agent": {"running": agent_pid is not None, "pid": agent_pid},
        "protected": holdfs_pid is not None and mounted,
    }
