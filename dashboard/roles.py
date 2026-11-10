"""
웹 시연이 등록한 작업 프로세스의 역할 (프로세스 이름 대신 lolbin_attack 같은 역할을 보여준다)

demo-web runner 가 프로세스를 등록할 때 PROCESS_ROLES_PATH 에 한 줄씩 남긴다
({"pid", "start_time_ticks", "role", "scenario_id", "run_id", "workspace", "registered_ts"}).
이벤트의 PID 와 시각으로 가장 최근 등록을 찾는다. PID 는 재사용될 수 있으므로
등록 시각 이후, ROLE_WINDOW_SEC 안의 이벤트에만 붙인다.
"""

from __future__ import annotations

import json
import os
import sys
import threading

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
try:
    from guardfs.common.paths import PROCESS_ROLES_PATH
except ImportError:
    PROCESS_ROLES_PATH = os.path.expanduser("~/guardfs_runtime/process_roles.jsonl")

ROLE_WINDOW_SEC = 2 * 3600   # 등록 후 이 시간 안의 이벤트에만 역할을 붙인다 (시나리오 실행은 길어야 몇 분)
CLOCK_SLACK_SEC = 2          # 등록 기록과 이벤트 시각의 작은 차이 허용
MAX_LINES = 20000            # 파일이 커져도 최근 기록만 읽는다


class RoleIndex:
    def __init__(self, path: str | None = None):
        self.path = path or os.environ.get("DASH_PROCESS_ROLES", PROCESS_ROLES_PATH)
        self._sig = None
        self._by_pid: dict[int, list[dict]] = {}
        self._lock = threading.Lock()

    def _reload(self) -> None:
        try:
            st = os.stat(self.path)
        except OSError:
            self._sig, self._by_pid = None, {}
            return
        sig = (st.st_ino, st.st_size, st.st_mtime)
        if sig == self._sig:
            return
        by_pid: dict[int, list[dict]] = {}
        try:
            with open(self.path, encoding="utf-8") as f:
                lines = f.readlines()[-MAX_LINES:]
        except OSError:
            return
        for line in lines:
            try:
                e = json.loads(line)
                pid, role, ts = int(e["pid"]), str(e["role"]), float(e["registered_ts"])
            except (ValueError, KeyError, TypeError):
                continue  # 깨진 줄은 건너뛴다
            if pid > 0 and role:
                by_pid.setdefault(pid, []).append({**e, "pid": pid, "role": role, "registered_ts": ts})
        self._sig, self._by_pid = sig, by_pid

    def lookup(self, pid: int, ts: float) -> dict | None:
        """이벤트 시각 ts(초) 기준으로 그 PID 의 가장 최근 등록. 없으면 None."""
        with self._lock:
            self._reload()
            hits = [e for e in self._by_pid.get(pid, ())
                    if e["registered_ts"] - CLOCK_SLACK_SEC <= ts <= e["registered_ts"] + ROLE_WINDOW_SEC]
        return max(hits, key=lambda e: e["registered_ts"]) if hits else None
