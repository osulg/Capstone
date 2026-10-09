"""
CCCV EDR 에이전트

GuardFS가 남기는 로그를 tail 하면서 MEDIUM / HIGH 이벤트를 JSON으로 변환해
대시보드 서버(POST /api/events)로 전송한다. GuardFS 코드는 수정하지 않는다.

수집 소스
1. ~/filesecurity.log (기본)
   medium.py / high.py 의 log_medium_event / log_high_event 가 쓰는
   [MEDIUM] / [HIGH] 블록 → 정책 수행 결과 (BUFFERED, BLOCKED, DROP ...)
2. GuardFS 표준출력 로그 (선택, --stdout-log)
   [STAGE2] / [WATCH] / [REEVAL] / [TRIGGER HIGH] / [TRUST] 줄 → 상태 격상 이벤트와
   그 이유(ML 점수, Stage1 탐지기, magic mismatch 등)

사용 예:
    python dashboard/agent.py                                  # filesecurity.log만
    python dashboard/agent.py --stdout-log ~/guardfs_stdout.log
    python dashboard/agent.py --demo                           # 샘플 이벤트 전송
"""

import argparse
import json
import os
import re
import socket
import time
import urllib.error
import urllib.request

HOST = socket.gethostname()


def now_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def process_name(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/comm", "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return "-"


# --------------------------------------------------------------------------- #
# 전송
# --------------------------------------------------------------------------- #

class Sender:
    def __init__(self, server: str):
        self.url = server.rstrip("/") + "/api/events"
        self.queue = []

    def push(self, ev: dict) -> None:
        ev.setdefault("host", HOST)
        self.queue.append(ev)
        print(f"[AGENT] {ev['level']:<6} pid={ev['pid']} {ev['action']} {ev['result']} "
              f"{ev.get('target') or ''} {ev.get('reason') or ''}")

    def flush(self) -> None:
        if not self.queue:
            return
        data = json.dumps(self.queue, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(self.url, data=data,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                resp.read()
            self.queue.clear()
        except (urllib.error.URLError, OSError) as e:
            # 서버가 아직 안 떠 있으면 큐에 보관했다가 다음 주기에 재전송
            print(f"[AGENT] 전송 실패 ({e}), {len(self.queue)}건 보관 후 재시도")


# --------------------------------------------------------------------------- #
# 파일 tail
# --------------------------------------------------------------------------- #

class Tail:
    """로그 파일을 따라가며 새 줄을 돌려준다. 파일 생성/truncate/교체를 처리한다."""

    def __init__(self, path: str, from_start: bool):
        self.path = os.path.expanduser(path)
        self.from_start = from_start
        self.f = None
        self.inode = None
        self.buf = ""

    def _open(self) -> bool:
        try:
            self.f = open(self.path, "r", encoding="utf-8", errors="replace")
        except OSError:
            return False
        self.inode = os.fstat(self.f.fileno()).st_ino
        if not self.from_start:
            self.f.seek(0, os.SEEK_END)
        self.from_start = True  # 재오픈(로테이션) 이후에는 처음부터 읽는다
        return True

    def lines(self) -> list:
        if self.f is None and not self._open():
            return []
        try:
            st = os.stat(self.path)
            if st.st_ino != self.inode or st.st_size < self.f.tell():
                self.f.close()
                self.f = None
                self.buf = ""
                if not self._open():
                    return []
        except OSError:
            return []
        chunk = self.f.read()
        if not chunk:
            return []
        self.buf += chunk
        *complete, self.buf = self.buf.split("\n")
        return complete


# --------------------------------------------------------------------------- #
# filesecurity.log 파서 ([HIGH] / [MEDIUM] 블록)
# --------------------------------------------------------------------------- #

class SecurityLogParser:
    KEYS = {"Time": "time", "PID": "pid", "Process": "process", "Target": "target",
            "Action": "action", "Result": "result", "Reason": "reason"}

    def __init__(self):
        self.cur = None

    def feed(self, line: str):
        line = line.rstrip("\r")
        if line in ("[HIGH]", "[MEDIUM]"):
            done = self._finish()
            self.cur = {"level": line.strip("[]")}
            return done
        if self.cur is None:
            return None
        if not line.strip():
            return self._finish()
        key, sep, val = line.partition(": ")
        if sep and key in self.KEYS:
            self.cur[self.KEYS[key]] = val.strip()
        return None

    def _finish(self):
        ev, self.cur = self.cur, None
        if not ev or "pid" not in ev:
            return None
        ev["pid"] = int(ev["pid"]) if ev["pid"].isdigit() else 0
        if not ev.get("process"):
            ev["process"] = process_name(ev["pid"])
        ev["source"] = "filesecurity"
        return ev


# --------------------------------------------------------------------------- #
# GuardFS stdout 파서 (상태 격상과 이유)
# --------------------------------------------------------------------------- #

RE_SUSPECT = re.compile(r"\[STATE\] pid=(\d+) LOW -> SUSPICIOUS reason=(\S*)")
RE_SCORE = re.compile(r"\[(?:STAGE2|WATCH|REEVAL)\] pid=(\d+) dyn=([\d.]+) stat=([\d.]+) "
                      r"(?:final|score)=([\d.]+)")
RE_TO_MEDIUM = re.compile(r"\[(STAGE2|WATCH)\] pid=(\d+) → MEDIUM \(score=([\d.]+)\)")
RE_TRUST = re.compile(r"\[TRUST\] pid=(\d+) untrusted origin → forced MEDIUM")
RE_HIGH = re.compile(r"\[TRIGGER HIGH\] pid=(\d+) reason=(.*)$")
RE_SUSPEND = re.compile(r"\[HIGH\] pid=(\d+) suspend 완료")
RE_LOW_REEVAL = re.compile(r"\[REEVAL\] pid=(\d+) 10초 경과 → Low 복귀")
RE_LOW_WATCH = re.compile(r"\[WATCH\] pid=(\d+) 관찰 종료")


class StdoutParser:
    def __init__(self):
        self.stage1_reason = {}   # pid -> Stage1 탐지기
        self.scores = {}          # pid -> (dyn, stat, score)
        self.level = {}           # pid -> 마지막으로 보낸 상태

    def _ev(self, pid, level, result, reason, action="ESCALATE"):
        self.level[pid] = level
        return {"time": now_str(), "level": level, "pid": pid, "process": process_name(pid),
                "target": "", "action": action, "result": result, "reason": reason,
                "source": "stdout"}

    def _score_text(self, pid):
        s = self.scores.get(pid)
        return f"dyn={s[0]:.3f} stat={s[1]:.3f} score={s[2]:.3f}" if s else ""

    def _join(self, *parts):
        return ", ".join(p for p in parts if p)

    def feed(self, line: str):
        m = RE_SUSPECT.search(line)
        if m:
            self.stage1_reason[int(m.group(1))] = m.group(2)
            return None
        m = RE_SCORE.search(line)
        if m:
            self.scores[int(m.group(1))] = tuple(float(x) for x in m.group(2, 3, 4))
            return None
        m = RE_TO_MEDIUM.search(line)
        if m:
            pid = int(m.group(2))
            stage = "Stage2 최초 평가" if m.group(1) == "STAGE2" else "관찰 창 재채점"
            s1 = self.stage1_reason.get(pid)
            return self._ev(pid, "MEDIUM", "MEDIUM", self._join(
                f"stage1={s1}" if s1 else "", f"{stage} score={m.group(3)}", self._score_text(pid)))
        m = RE_TRUST.search(line)
        if m:
            pid = int(m.group(1))
            if self.level.get(pid) in ("MEDIUM", "HIGH"):
                return None
            return self._ev(pid, "MEDIUM", "MEDIUM", "untrusted_origin (비신뢰 실행 경로 → 선제 MEDIUM)")
        m = RE_HIGH.search(line)
        if m:
            pid = int(m.group(1))
            s1 = self.stage1_reason.get(pid)
            return self._ev(pid, "HIGH", "HIGH", self._join(
                m.group(2).strip(), f"stage1={s1}" if s1 else "", self._score_text(pid)))
        m = RE_SUSPEND.search(line)
        if m:
            pid = int(m.group(1))
            return self._ev(pid, "HIGH", "SUSPENDED", "SIGSTOP 일시정지", action="SIGSTOP")
        m = RE_LOW_REEVAL.search(line) or RE_LOW_WATCH.search(line)
        if m:
            pid = int(m.group(1))
            if self.level.get(pid) not in ("MEDIUM", "HIGH"):
                return None  # MEDIUM/HIGH를 거치지 않은 PID의 관찰 종료는 표시하지 않음
            return self._ev(pid, "LOW", "LOW", self._join("재평가 후 정상 판정", self._score_text(pid)),
                            action="RETURN")
        return None


# --------------------------------------------------------------------------- #
# 데모
# --------------------------------------------------------------------------- #

def run_demo(sender: Sender, delay: float) -> None:
    """발표 화면과 같은 시나리오(python3 스크립트형 랜섬웨어)를 순서대로 전송한다."""
    pid = 905425
    base = os.path.expanduser("~/guardfs_runtime/underlay")
    seq = [
        dict(level="MEDIUM", action="ESCALATE", result="MEDIUM", target="",
             reason="stage1=EntropyBurstDetector, Stage2 최초 평가 score=0.412, "
                    "dyn=0.471 stat=0.353 score=0.412"),
    ]
    for i in range(1, 6):
        seq.append(dict(level="MEDIUM", action="WRITE", result="BUFFERED",
                        target=f"{base}/victim_{i}.txt",
                        reason="size=512 trusted=False ext_group=PLAIN_TEXT"))
    seq += [
        dict(level="HIGH", action="ESCALATE", result="HIGH", target="",
             reason="reeval_score=0.837, stage1=EntropyBurstDetector, "
                    "dyn=0.912 stat=0.762 score=0.837"),
        dict(level="MEDIUM", action="DROP", result="BUFFER_DROPPED", target="",
             reason="버퍼 5개 드롭, 원본 보존"),
        dict(level="HIGH", action="SIGSTOP", result="SUSPENDED", target="", reason="SIGSTOP 일시정지"),
        dict(level="HIGH", action="WRITE", result="BLOCKED", target=f"{base}/victim_6.txt",
             reason="reeval_score=0.837"),
    ]
    for item in seq:
        ev = {"time": now_str(), "pid": pid, "process": "python3", "source": "demo", **item}
        sender.push(ev)
        sender.flush()
        time.sleep(delay)


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main() -> None:
    ap = argparse.ArgumentParser(description="CCCV EDR agent (GuardFS log → dashboard)")
    ap.add_argument("--server", default="http://127.0.0.1:5000")
    ap.add_argument("--security-log", default="~/filesecurity.log",
                    help="GuardFS MEDIUM/HIGH 정책 로그 (기본: ~/filesecurity.log)")
    ap.add_argument("--stdout-log", default=None,
                    help="GuardFS 표준출력을 tee로 저장한 파일 (격상 이유 수집용)")
    ap.add_argument("--from-start", action="store_true",
                    help="로그 파일을 처음부터 읽어 기존 이벤트도 전송")
    ap.add_argument("--interval", type=float, default=0.5)
    ap.add_argument("--demo", action="store_true", help="샘플 이벤트를 전송하고 종료")
    ap.add_argument("--demo-delay", type=float, default=0.8)
    args = ap.parse_args()

    sender = Sender(args.server)

    if args.demo:
        run_demo(sender, args.demo_delay)
        return

    sources = [(Tail(args.security_log, args.from_start), SecurityLogParser())]
    if args.stdout_log:
        sources.append((Tail(args.stdout_log, args.from_start), StdoutParser()))

    print(f"[AGENT] server={args.server}")
    for tail, _ in sources:
        print(f"[AGENT] watching {tail.path}")

    try:
        while True:
            for tail, parser in sources:
                for line in tail.lines():
                    ev = parser.feed(line)
                    if ev:
                        sender.push(ev)
            sender.flush()
            time.sleep(args.interval)
    except KeyboardInterrupt:
        sender.flush()


if __name__ == "__main__":
    main()
