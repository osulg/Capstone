"""
SensitivePathDetector
- /etc/passwd, /etc/shadow, ~/.ssh/ 등 민감한 시스템 경로에
  open/read 접근이 발생하면 탐지
- MITRE ATT&CK T1003.008 (OS Credential Dumping) 대응
"""

import os

# 탐지할 민감 경로 목록 (절대 경로 또는 경로 접두사)
SENSITIVE_PATHS = [
    # 크리덴셜 관련
    "/etc/passwd",
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",

    # SSH 키
    os.path.expanduser("~/.ssh"),
    "/root/.ssh",

    # 인증서 / 키
    "/etc/ssl/private",

    # 시스템 설정
    "/etc/crontab",
    "/etc/cron.d",
    "/var/spool/cron",
]


class SensitivePathDetector:
    def __init__(self):
        # 모두 realpath로 정규화
        self._sensitive = [os.path.realpath(p) for p in SENSITIVE_PATHS]

    def check(self, ev) -> bool:
        if ev.op not in ("open", "read", "lookup"):
            return False

        target = os.path.realpath(ev.path)

        for sensitive in self._sensitive:
            # 정확히 일치하거나, 해당 경로의 하위인 경우 탐지
            if target == sensitive or target.startswith(sensitive + os.sep):
                return True

        return False
