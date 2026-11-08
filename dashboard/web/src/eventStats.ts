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

// HoldFS 는 감시가 끝날 때마다 반영 단계를 돌고, 반영할 쓰기가 없어도 '반영 완료(DATA_APPLIED)'를 남긴다.
// 그 감시 구간(마지막 MEDIUM 격상 이후)에 실제로 반영된 파일(FILE_APPLIED)이 없으면 뺀다.
// rows 는 한 PID 의 기록을 시간순으로 넣는다.
export function dropEmptyCommit(rows: EdrEvent[]): EdrEvent[] {
  let applied = false;
  return rows.filter((e) => {
    if (e.action === "ESCALATE" && e.level === "MEDIUM") applied = false;
    if (e.result === "FILE_APPLIED") applied = true;
    if (e.result === "DATA_APPLIED") { const keep = applied; applied = false; return keep; }
    return true;
  });
}

// 화면에 보여줄 기록만 남긴다. 그래프·PID 목록·파일 목록·상세가 모두 이 기준을 쓴다.
//  - isHiddenEvent (반영 전 다시 지운 새 파일, '버퍼 0개 드롭')
//  - PID 별로 dropEmptyCommit (반영한 파일이 없는 '반영 완료')
export function shownEvents(events: EdrEvent[]): EdrEvent[] {
  const perPid = new Map<number, EdrEvent[]>();
  for (const e of events) {
    if (isHiddenEvent(e)) continue;
    const list = perPid.get(e.pid);
    if (list) list.push(e); else perPid.set(e.pid, [e]);
  }
  const out: EdrEvent[] = [];
  for (const list of perPid.values()) out.push(...dropEmptyCommit([...list].sort((a, b) => a.time.localeCompare(b.time))));
  return out;
}

// PID 별 목록 (shownEvents 를 거친 기록을 넣는다). 마지막 활동이 최근인 순으로 정렬한다.
export function byPid(events: EdrEvent[]): PidRow[] {
  const perPid = new Map<number, EdrEvent[]>();
  for (const e of shownEvents(events)) {
    const list = perPid.get(e.pid);
    if (list) list.push(e); else perPid.set(e.pid, [e]);
  }
  const rows: PidRow[] = [];
  for (const [pid, shown] of perPid) {
    const r: PidRow = { pid, process: shown[0].process, level: "LOW", count: shown.length, last: "", lastTime: "" };
    for (const e of shown) {
      if ((LEVEL_RANK[e.level] ?? 0) > (LEVEL_RANK[r.level] ?? 0)) r.level = e.level;
      if (e.process && e.process !== "-") r.process = e.process;
    }
    const last = shown[shown.length - 1];
    r.last = `${last.action} ${last.result}`.trim();
    r.lastTime = last.time;
    rows.push(r);
  }
  return rows.sort((a, b) => b.lastTime.localeCompare(a.lastTime));
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

// 화면에서 아예 숨기는 기록 (원본에 영향 없음)
//  - MEDIUM 중 새로 만든 파일을 반영 전에 다시 지운 것
//  - HIGH 진입 때 버릴 보류 쓰기가 없어 남는 '버퍼 0개 드롭'
export const isHiddenEvent = (e: EdrEvent) =>
  e.result === "REMOVED_PENDING" || (e.result === "BUFFER_DROPPED" && /버퍼 0개/.test(e.reason || ""));

// 화면에 보여줄 위험도. HoldFS 는 판정 뒤 정리 기록도 MEDIUM 정책 코드에서 남겨 [MEDIUM] 으로 적는다.
// 실제 그때 상태로 바꿔 보여준다: HIGH 때문에 정리된 것(폐기·복원) → HIGH,
// 정상 판정 뒤 반영·확정된 것 → LOW. (격상 원인인 VALIDATION_FAILED 는 그때 MEDIUM 이므로 그대로)
const AFTER_HIGH = new Set(["BUFFER_DROPPED", "RESTORED", "RESTORE_CONFLICT", "RESTORE_FAILED", "RESTORE_CLEANUP_FAILED"]);
const AFTER_LOW = new Set(["FILE_APPLIED", "DATA_APPLIED", "STAGING_PRESERVED", "APPLY_FAILED", "IO_FAILED",
  "NOT_COMPLETED", "HANDLE_CLEANUP_FAILED", "CONFIRMED", "FINALIZE_FAILED"]);
export function displayLevel(e: EdrEvent): string {
  if (e.level !== "MEDIUM") return e.level;
  if (e.action === "DROP" || AFTER_HIGH.has(e.result)) return "HIGH";
  if (AFTER_LOW.has(e.result) || (e.action === "COMMIT" && e.result === "CLEANUP_FAILED")) return "LOW";
  return e.level;
}

// 파일 입장의 현재 상태: 그 파일 기록을 시간순으로 보며 마지막 상태를 정한다.
//  원본 보존 / 차단 / 판정 대기 / 반영됨 / 삭제됨 / 미끼 접근 / 확인 필요, 폴더는 "-"
export type FileStatus = "원본 보존" | "차단" | "판정 대기" | "반영됨" | "삭제됨" | "미끼 접근" | "확인 필요" | "-";
const NEEDS_CHECK = new Set(["RESTORE_CONFLICT", "STAGING_PRESERVED", "RESTORE_FAILED", "RESTORE_CLEANUP_FAILED",
  "APPLY_FAILED", "IO_FAILED", "NOT_COMPLETED", "FINALIZE_FAILED"]);
export function fileStatus(rows: EdrEvent[], dropped: Set<number>): FileStatus {
  let st: FileStatus = "-";
  for (const e of rows) {
    if (e.action === "MKDIR" || e.action === "RMDIR") continue;           // 폴더는 상태를 매기지 않는다
    if (/honeypot/i.test(e.reason || "")) st = "미끼 접근";
    else if (e.result === "BLOCKED") st = "차단";
    else if (e.result === "ESCALATED_TO_HIGH" || e.result === "VALIDATION_FAILED" || e.result === "RESTORED") st = "원본 보존";
    else if (e.result === "BUFFERED" || e.result === "STAGED") st = dropped.has(e.pid) ? "원본 보존" : "판정 대기";
    else if (e.result === "FILE_APPLIED" || (e.action === "SETATTR" && e.result === "CONFIRMED")) st = "반영됨";
    else if (e.action === "UNLINK" && e.result === "CONFIRMED") st = "삭제됨";
    else if (NEEDS_CHECK.has(e.result)) st = "확인 필요";
  }
  return st;
}

// 파일 단위로 묶을 때 쓰는 열쇠. 이름 변경 기록("원래 경로 -> 새 경로")은 원래 파일의 기록으로 본다.
export const fileKey = (target: string) => target.split(/ (?:->|→) /)[0];

export function byFile(events: EdrEvent[]): FileRow[] {
  const dropped = droppedPids(events);
  const byTarget = new Map<string, EdrEvent[]>();
  for (const e of events) {
    if (!e.target || isHiddenEvent(e)) continue;
    const key = fileKey(e.target);
    const list = byTarget.get(key);
    if (list) list.push(e); else byTarget.set(key, [e]);
  }
  const rows: FileRow[] = [];
  for (const [target, list] of byTarget) {
    const sorted = [...list].sort((a, b) => a.time.localeCompare(b.time));
    const last = sorted[sorted.length - 1];
    const result = fileStatus(sorted, dropped);
    rows.push({
      target, short: shortPath(target), process: `${last.process} (${last.pid})`,
      action: last.action, result, danger: result === "차단", time: last.time,
    });
  }
  return rows.sort((a, b) => b.time.localeCompare(a.time));
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