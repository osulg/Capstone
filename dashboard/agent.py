"""
HoldFS EDR 에이전트

HoldFS가 남기는 로그를 tail 하면서 MEDIUM / HIGH 이벤트를 JSON으로 변환해
대시보드 서버(POST /api/events)로 전송한다. HoldFS 코드는 수정하지 않는다.

수집 소스
1. ~/filesecurity.log (기본)
   medium.py / high.py 의 log_medium_event / log_high_event 가 쓰는
   [MEDIUM] / [HIGH] 블록 → 정책 수행 결과 (BUFFERED, BLOCKED, DROP ...)
2. HoldFS 표준출력 로그 (선택, --stdout-log)
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


def _read_comm(pid: int) -> str | None:
    try:
        with open(f"/proc/{pid}/comm", "r", encoding="utf-8") as f:
            return f.read().strip() or None
    except OSError:
        return None


def process_name(pid: int) -> str:
    """PID 의 프로세스 이름.

    FUSE 가 넘겨주는 pid 는 요청을 보낸 '스레드' 번호라서 comm 을 그대로 읽으면
    'pool' 같은 작업 스레드 이름이 나올 수 있다. /proc/<pid>/status 의 Tgid(스레드가 속한
    프로세스 번호)로 실제 프로세스 이름(예: nautilus)을 읽는다. 이미 끝난 프로세스면 '-'.
    """
    tgid = pid
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("Tgid:"):
                    tgid = int(line.split()[1])
                    break
    except (OSError, ValueError):
        pass
    return _read_comm(tgid) or _read_comm(pid) or "-"


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
        # HoldFS 가 적은 Process 도 스레드 이름일 수 있어, 읽을 수 있으면 실제 프로세스 이름을 쓴다
        name = process_name(ev["pid"])
        if name != "-" or not ev.get("process"):
            ev["process"] = name
        ev["source"] = "filesecurity"
        return ev


# --------------------------------------------------------------------------- #
# HoldFS stdout 파서 (상태 격상과 이유)
# --------------------------------------------------------------------------- #

RE_SUSPECT = re.compile(r"\[STATE\] pid=(\d+) LOW -> SUSPICIOUS reason=(\S*)")
RE_SCORE = re.compile(r"\[(?:STAGE2|WATCH|REEVAL)\] pid=(\d+) dyn=([\d.]+) stat=([\d.]+) "
                      r"(?:final|score)=([\d.]+)")
RE_TO_MEDIUM = re.compile(r"\[(STAGE2|WATCH)\] pid=(\d+) → MEDIUM \(score=([\d.]+)\)")
# 상태가 MEDIUM 으로 바뀐 줄. 비신뢰 실행 경로라서 판정 전에 먼저 MEDIUM 이 되면 LOW 또는
# SUSPICIOUS(stage1_sampling 등으로 먼저 의심 대상이 된 경우)에서 바뀐다.
# Stage2/관찰 창 판정으로 MEDIUM 이 될 때도 SUSPICIOUS → MEDIUM 이 찍히는데, 그때는 같은 PID 의
# 점수 줄([STAGE2]/[WATCH] … dyn= stat=) 바로 다음에 나오고 이어서 '→ MEDIUM (score=…)' 줄이 나온다.
RE_TRUST = re.compile(r"\[STATE\] pid=(\d+) ProcState\.(LOW|SUSPICIOUS) → ProcState\.MEDIUM")
RE_LINE_PID = re.compile(r"\bpid=(\d+)")
RE_HIGH = re.compile(r"\[TRIGGER HIGH\] pid=(\d+) reason=(.*)$")
RE_SUSPEND = re.compile(r"\[HIGH\] pid=(\d+) suspend 완료")
RE_LOW_REEVAL = re.compile(r"\[REEVAL\] pid=(\d+) (?:관찰 시간 종료 → LOW|10초 경과 → Low) 복귀")
RE_LOW_WATCH = re.compile(r"\[WATCH\] pid=(\d+) 관찰 종료")
# passthrough.py: 허니팟 경로에 대한 open/read/write/truncate/unlink/rmdir/rename 차단
RE_HONEYPOT = re.compile(r"\[HONEYPOT\] pid=(\d+) op=(\S+) blocked path=(.+?)(?: new_path=(.+))?$")

HONEYPOT_REASON = "HoneypotDetector: 허니팟(미끼) 파일 접근 차단"
HONEYPOT_DEDUP_SEC = 2.0


# run_all.sh 가 HoldFS 실행 출력 각 줄 앞에 붙이는 출력 시각 ("YYYY-MM-DD HH:MM:SS ")
RE_LINE_TIME = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (.*)$")


class StdoutParser:
    def __init__(self):
        self.stage1_reason = {}   # pid -> Stage1 탐지기
        self.scores = {}          # pid -> (dyn, stat, score)
        self.level = {}           # pid -> 마지막으로 보낸 상태
        self.honeypot_seen = {}   # (pid, op, path) -> 마지막 전송 시각 (같은 접근 반복 표시 방지)
        self.line_time = None     # 지금 읽는 줄에 붙은 HoldFS 출력 시각 (없으면 agent가 읽은 시각)
        self.prev_was_score = {}  # pid -> 이 PID 의 바로 앞 줄이 Stage2/관찰 창 점수 줄이었는지
        self.medium_sent = set()  # 이번 감시 구간에 MEDIUM 격상 이벤트를 이미 보낸 PID (정상 복귀 시 해제)

    def _ev(self, pid, level, result, reason, action="ESCALATE"):
        if level != "SUSPICIOUS":  # 허니팟 표시 행이 MEDIUM/HIGH 추적을 덮어쓰지 않도록
            self.level[pid] = level
        if action == "ESCALATE" and level == "MEDIUM":
            self.medium_sent.add(pid)
        elif action == "RETURN":
            self.medium_sent.discard(pid)
        return {"time": self.line_time or now_str(), "level": level, "pid": pid, "process": process_name(pid),
                "target": "", "action": action, "result": result, "reason": reason,
                "source": "stdout"}

    # MEDIUM 상태에서만 남는 정책 기록 (보류/지연/보관). 반영·폐기·복원처럼 판정 뒤에 남는 기록은 제외.
    MEDIUM_ENTRY_RESULTS = {"BUFFERED", "ALLOWED", "STAGED", "REMOVED_PENDING", "ESCALATED_TO_HIGH"}

    def medium_entry(self, sec_ev: dict):
        """filesecurity.log 의 MEDIUM 정책 기록을 보고, 아직 MEDIUM 기록을 보내지 않은 PID 면
        MEDIUM 격상 이벤트를 만든다.

        비신뢰 경로 프로세스가 Stage1 에서 먼저 SUSPICIOUS 가 되면, HoldFS 는 상태를 바꾸지 않고
        실행할 때만 MEDIUM 으로 취급한다(passthrough.py _resolve_suspicious_state). 이때는 실행
        출력에 MEDIUM 진입 줄이 없으므로 정책 기록이 MEDIUM 진입의 유일한 신호다.
        """
        pid = sec_ev.get("pid", 0)
        if sec_ev.get("level") != "MEDIUM" or sec_ev.get("result") not in self.MEDIUM_ENTRY_RESULTS:
            return None
        # 실행 출력을 먼저 읽기 때문에 같은 순간의 HIGH 격상이 이미 처리됐을 수 있다.
        # 그래서 '지금 상태'가 아니라 'MEDIUM 격상을 보낸 적이 있는지'로 판단한다.
        if not pid or pid in self.medium_sent or self.level.get(pid) == "MEDIUM":
            return None
        s1 = self.stage1_reason.get(pid)
        was = self.level.get(pid)
        saved, self.line_time = self.line_time, sec_ev.get("time")
        ev = self._ev(pid, "MEDIUM", "MEDIUM", self._join(
            "untrusted_origin (비신뢰 실행 경로 → 선제 MEDIUM, 또는 강제 상태 파일)",
            f"stage1={s1}" if s1 else ""))
        self.line_time = saved
        if was == "HIGH":
            self.level[pid] = "HIGH"  # 이미 HIGH 면 상태 추적은 HIGH 로 둔다
        return ev

    def _score_text(self, pid):
        s = self.scores.get(pid)
        return f"dyn={s[0]:.3f} stat={s[1]:.3f} score={s[2]:.3f}" if s else ""

    def _join(self, *parts):
        return ", ".join(p for p in parts if p)

    def feed(self, line: str):
        # 줄 앞에 출력 시각이 붙어 있으면 그 시각을 이벤트 시각으로 쓴다.
        # (실행 출력에는 HoldFS 자체 시각이 없어서, agent가 읽은 시각을 쓰면 최대 1초쯤 늦어진다)
        t = RE_LINE_TIME.match(line)
        self.line_time, line = (t.group(1), t.group(2)) if t else (None, line)
        p = RE_LINE_PID.search(line)
        if not p:
            return self._parse(line, None)
        pid = int(p.group(1))
        prev_score = self.prev_was_score.get(pid, False)
        self.prev_was_score[pid] = bool(re.match(r"\[(?:STAGE2|WATCH)\] pid=\d+ dyn=", line))
        return self._parse(line, prev_score)

    def _parse(self, line: str, prev_score):
        m = RE_HONEYPOT.search(line)
        if m:
            pid, op, path, new_path = int(m.group(1)), m.group(2), m.group(3), m.group(4)
            key = (pid, op, path)
            now = time.time()
            if now - self.honeypot_seen.get(key, 0) < HONEYPOT_DEDUP_SEC:
                return None
            self.honeypot_seen[key] = now
            ev = self._ev(pid, "SUSPICIOUS", "BLOCKED", HONEYPOT_REASON, action=op.upper())
            ev["target"] = f"{path} → {new_path}" if new_path else path
            return ev
        m = RE_SUSPECT.search(line)
        if m:
            pid, reason = int(m.group(1)), m.group(2)
            self.stage1_reason[pid] = reason
            # 허니팟 안 create/mkdir 처럼 차단 없이 관찰만 되는 접근도 Stage1 탐지는 보이게 한다.
            if reason == "HoneypotDetector":
                return self._ev(pid, "SUSPICIOUS", "SUSPICIOUS",
                                "HoneypotDetector: 허니팟 접근 탐지 → Stage2 평가 요청", action="DETECT")
            return None
        m = RE_SCORE.search(line)
        if m:
            self.scores[int(m.group(1))] = tuple(float(x) for x in m.group(2, 3, 4))
            return None
        m = RE_TO_MEDIUM.search(line)
        if m:
            pid = int(m.group(2))
            if self.level.get(pid) == "MEDIUM":
                return None  # 이미 비신뢰 경로로 MEDIUM 기록을 보냄
            stage = "Stage2 최초 평가" if m.group(1) == "STAGE2" else "관찰 창 재채점"
            s1 = self.stage1_reason.get(pid)
            return self._ev(pid, "MEDIUM", "MEDIUM", self._join(
                f"stage1={s1}" if s1 else "", f"{stage} score={m.group(3)}", self._score_text(pid)))
        m = RE_TRUST.search(line)
        if m:
            pid = int(m.group(1))
            if self.level.get(pid) in ("MEDIUM", "HIGH"):
                return None
            if m.group(2) == "SUSPICIOUS" and prev_score:
                return None  # Stage2/관찰 창 판정: 다음 '→ MEDIUM (score=…)' 줄에서 기록한다
            s1 = self.stage1_reason.get(pid)
            return self._ev(pid, "MEDIUM", "MEDIUM", self._join(
                "untrusted_origin (비신뢰 실행 경로 → 선제 MEDIUM, 또는 강제 상태 파일)",
                f"stage1={s1}" if s1 else ""))
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
    ap = argparse.ArgumentParser(description="HoldFS EDR agent (HoldFS log → dashboard)")
    ap.add_argument("--server", default="http://127.0.0.1:5000")
    ap.add_argument("--security-log", default="~/filesecurity.log",
                    help="HoldFS MEDIUM/HIGH 정책 로그 (기본: ~/filesecurity.log)")
    ap.add_argument("--stdout-log", default=None,
                    help="HoldFS 표준출력을 tee로 저장한 파일 (격상 이유 수집용)")
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

    # 실행 출력을 먼저 읽는다: 상태 변화 줄(Stage2 MEDIUM 판정 등)을 정책 기록보다 먼저 반영해야
    # medium_entry() 가 Stage2 MEDIUM 을 비신뢰 경로 MEDIUM 으로 잘못 보내지 않는다.
    sources = []
    stdout_parser = None
    if args.stdout_log:
        stdout_parser = StdoutParser()
        sources.append((Tail(args.stdout_log, args.from_start), stdout_parser))
    sources.append((Tail(args.security_log, args.from_start), SecurityLogParser()))

    print(f"[AGENT] server={args.server}")
    for tail, _ in sources:
        print(f"[AGENT] watching {tail.path}")

    try:
        while True:
            for tail, parser in sources:
                for line in tail.lines():
                    ev = parser.feed(line)
                    if not ev:
                        continue
                    if stdout_parser and parser is not stdout_parser:
                        entry = stdout_parser.medium_entry(ev)
                        if entry:
                            sender.push(entry)
                    sender.push(ev)
            sender.flush()
            time.sleep(args.interval)
    except KeyboardInterrupt:
        sender.flush()


if __name__ == "__main__":
    main()
