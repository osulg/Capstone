// 이벤트 배열을 화면용으로 묶는 함수들 (보안 이벤트 현황 탭)
import type { EdrEvent } from "./types";

export const LEVEL_RANK: Record<string, number> = { HIGH: 3, MEDIUM: 2, SUSPICIOUS: 1, LOW: 0 };

export const eventDate = (e: EdrEvent) => new Date(e.time.replace(" ", "T"));

export type Period = "10m" | "1h" | "today";

export const PERIODS: [Period, string][] = [
  ["10m", "최근 10분"], ["1h", "최근 1시간"], ["today", "오늘"],
];

// 조회 기간의 시작 시각(ms)
export function periodStart(period: Period, now = new Date()): number {
  if (period === "today") return new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  return now.getTime() - (period === "10m" ? 10 : 60) * 60_000;
}

export function inPeriod(events: EdrEvent[], period: Period, now = new Date()): EdrEvent[] {
  const from = periodStart(period, now);
  return events.filter((e) => eventDate(e).getTime() >= from);
}

// 버퍼가 폐기된(원본이 보존된) PID 집합
export const droppedPids = (events: EdrEvent[]) =>
  new Set(events.filter((e) => e.result === "BUFFER_DROPPED").map((e) => e.pid));

export function summarize(events: EdrEvent[]) {
  const pidsAt = (level: string) => new Set(events.filter((e) => e.level === level).map((e) => e.pid));
  const high = pidsAt("HIGH");
  const medium = [...pidsAt("MEDIUM")].filter((p) => !high.has(p));
  const dropped = droppedPids(events);
  const kept = new Set(events.filter((e) => e.result === "BUFFERED" && dropped.has(e.pid) && e.target)
    .map((e) => e.target));
  return { high: high.size, medium: medium.length, kept: kept.size, total: events.length };
}

export interface PidRow {
  pid: number;
  process: string;
  level: string;
  count: number;
  last: string;
  lastTime: string;
}

export function byPid(events: EdrEvent[]): PidRow[] {
  const map = new Map<number, PidRow>();
  for (const e of events) {
    const r = map.get(e.pid) ?? { pid: e.pid, process: e.process, level: "LOW", count: 0, last: "", lastTime: "" };
    r.count += 1;
    if ((LEVEL_RANK[e.level] ?? 0) > (LEVEL_RANK[r.level] ?? 0)) r.level = e.level;
    if (e.process && e.process !== "-") r.process = e.process;
    r.last = `${e.action} ${e.result}`.trim();
    r.lastTime = e.time;
    map.set(e.pid, r);
  }
  return [...map.values()].sort((a, b) =>
    (LEVEL_RANK[b.level] ?? 0) - (LEVEL_RANK[a.level] ?? 0) || b.lastTime.localeCompare(a.lastTime));
}

export interface FileRow {
  target: string;
  short: string;
  process: string;
  action: string;
  result: string;
  danger: boolean;
  time: string;
}

// underlay 기준 상대 경로로 줄인다
// 이름 변경처럼 "원래 경로 -> 새 경로" 형태면 양쪽을 줄여 "a → b" 로 보여준다
export const shortPath = (p: string) =>
  p.split(/ (?:->|→) /).map((x) => x.replace(/^.*\/underlay\//, "")).join(" → ");

// 파일 입장에서 본 결과 이름 (파일별 목록과 파일 상세가 같이 쓴다)
export function fileResult(e: EdrEvent, dropped: Set<number>): string {
  if (/honeypot/i.test(e.reason || "")) return "미끼 접근";
  if (e.result === "BLOCKED") return "차단";
  if (e.result === "BUFFERED") return dropped.has(e.pid) ? "원본 보존" : "보류";
  return e.result;
}

export function byFile(events: EdrEvent[]): FileRow[] {
  const dropped = droppedPids(events);
  const map = new Map<string, FileRow>();
  for (const e of events) {
    if (!e.target) continue;
    const result = fileResult(e, dropped);
    map.set(e.target, {
      target: e.target, short: shortPath(e.target), process: `${e.process} (${e.pid})`,
      action: e.action, result, danger: e.result === "BLOCKED", time: e.time,
    });
  }
  return [...map.values()].sort((a, b) => b.time.localeCompare(a.time));
}

export interface Bucket { label: string; count: number; highs: EdrEvent[] }

// 조회 기간 시작(from)부터 지금(to)까지 분 단위 칸을 만든다. 이벤트가 없는 칸은 0.
// from이 없으면(전체) 첫 이벤트부터, 이벤트도 없으면 최근 10분을 보여준다.
// 구간이 길면 최대 maxPoints개가 되도록 묶음 크기를 키운다.
// 조회 기간 시작(from)부터 지금(to)까지 분 단위 칸을 만든다. 이벤트가 없는 칸은 0.
// 구간이 길면 최대 maxPoints개가 되도록 묶음 크기를 키운다.
export function buckets(events: EdrEvent[], from: number, to = Date.now(), maxPoints = 60): Bucket[] {
  const times = events.map((e) => eventDate(e).getTime());
  const min = Math.floor(from / 60_000);
  const max = Math.max(Math.floor(to / 60_000), ...times.map((t) => Math.floor(t / 60_000)));
  const span = max - min + 1;
  const step = Math.max(1, Math.ceil(span / maxPoints));
  const n = Math.ceil(span / step);
  const out: Bucket[] = Array.from({ length: n }, (_, i) => {
    const d = new Date((min + i * step) * 60_000);
    return { label: `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`, count: 0, highs: [] };
  });
  events.forEach((e, i) => {
    const b = out[Math.floor((Math.floor(times[i] / 60_000) - min) / step)];
    if (!b) return;
    b.count += 1;
    // 같은 PID의 HIGH 이벤트는 한 번만 보여준다. 격상(ESCALATE) 이벤트가 있으면 그걸 우선한다
    // (격상 사유에 Stage1 탐지기·점수·HIGH 사유가 모두 들어 있으므로)
    if (e.level === "HIGH") {
      const k = b.highs.findIndex((h) => h.pid === e.pid);
      if (k < 0) b.highs.push(e);
      else if (e.action === "ESCALATE" && b.highs[k].action !== "ESCALATE") b.highs[k] = e;
    }
  });
  return out;
}