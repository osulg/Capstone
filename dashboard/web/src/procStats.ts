// 시스템 현황 › 프로세스 상태: 오늘 이벤트로 PID별 현재 상태를 계산한다
import { isHoneypotBlock } from "./fileStats";
import type { EdrEvent } from "./types";

// MEDIUM은 보통 10초 안에 끝난다(정상 복귀·반영 또는 HIGH).
// 끝났다는 이벤트를 놓친 PID가 '감시 중'으로 계속 남지 않도록,
// 마지막 이벤트 후 이 시간이 지나면 감시 중에서 뺀다.
const MEDIUM_STALE_SEC = 120;

export interface ProcRow {
  pid: number;
  process: string;
  state: "MEDIUM" | "HIGH";
  since: string;          // 지금 상태로 들어온 시각
  score: string | null;   // 마지막 점수
  suspended: boolean;     // SIGSTOP 정지됨
}

export interface ProcSummary {
  medium: number;
  high: number;
  returned: number;
  honeypot: number;
  rows: ProcRow[];
}

const today = (now: Date) => {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${now.getFullYear()}-${p(now.getMonth() + 1)}-${p(now.getDate())}`;
};
const ms = (t: string) => new Date(t.replace(" ", "T")).getTime();

export function procSummary(events: EdrEvent[], now: Date): ProcSummary {
  const day = today(now);
  const todays = events.filter((e) => e.time.startsWith(day)).sort((a, b) => a.time.localeCompare(b.time));

  const byPid = new Map<number, EdrEvent[]>();
  for (const e of todays) {
    const list = byPid.get(e.pid);
    if (list) list.push(e); else byPid.set(e.pid, [e]);
  }

  const rows: ProcRow[] = [];
  let returned = 0;
  const honeypotPids = new Set<number>();
  for (const [pid, list] of byPid) {
    let state: "LOW" | "MEDIUM" | "HIGH" = "LOW";
    let since = "";
    let suspended = false;
    let didReturn = false;
    let score: string | null = null;
    let prev = 0;
    for (const e of list) {
      // MEDIUM 중 이벤트가 오래 끊겼으면 그 사이 끝난 것으로 보고 새로 센다
      const t = ms(e.time);
      if (state === "MEDIUM" && t - prev > MEDIUM_STALE_SEC * 1000) state = "LOW";
      prev = t;
      if (isHoneypotBlock(e)) honeypotPids.add(pid);
      const m = [...(e.reason || "").matchAll(/score=([\d.]+)/g)].pop();
      if (m) score = m[1];
      if (e.level === "HIGH") {
        if (state !== "HIGH") { state = "HIGH"; since = e.time; }
        if (e.result === "SUSPENDED") suspended = true;
      } else if (state === "HIGH") {
        continue;   // HIGH는 다시 내려오지 않는다
      } else if (e.action === "RETURN") {
        state = "LOW"; didReturn = true;
      } else if (e.level === "MEDIUM" && state === "LOW") {
        state = "MEDIUM"; since = e.time;
      }
    }
    if (didReturn) returned += 1;
    const last = list[list.length - 1];
    if (state === "MEDIUM" && now.getTime() - ms(last.time) > MEDIUM_STALE_SEC * 1000) continue;
    if (state === "LOW") continue;
    rows.push({
      pid, state, since, score, suspended,
      process: [...list].reverse().find((e) => e.process && e.process !== "-")?.process ?? "-",
    });
  }
  rows.sort((a, b) => (a.state === b.state ? b.since.localeCompare(a.since) : a.state === "HIGH" ? -1 : 1));
  return {
    medium: rows.filter((r) => r.state === "MEDIUM").length,
    high: rows.filter((r) => r.state === "HIGH").length,
    returned,
    honeypot: honeypotPids.size,
    rows,
  };
}
