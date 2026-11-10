// 파일 현황 탭에서 쓰는 계산 (폴더 스캔 결과 + HoldFS 이벤트)
import type { EdrEvent } from "./types";

export const hhmmss = (d: Date) =>
  [d.getHours(), d.getMinutes(), d.getSeconds()].map((n) => String(n).padStart(2, "0")).join(":");
export const fmtTime = (t: number) => hhmmss(new Date(t * 1000));

// 이벤트 시각 "YYYY-MM-DD HH:MM:SS" → ms
export const eventMs = (t: string) => new Date(t.replace(" ", "T")).getTime();

// 이벤트 대상 경로가 폴더 안 상대 경로(rel)의 파일인지.
// 이름 변경 이벤트는 "원래 경로 → 새 경로" 형태라 앞쪽만 본다.
export function sameFile(target: string, rel: string): boolean {
  const t = target.split(" → ")[0];
  return t === rel || t.endsWith("/" + rel);
}

// 파일 상세 화면에 넘길 대상 문자열: 이벤트에 실제로 찍힌 경로를 우선 쓴다.
// 이름이 바뀐 파일(예: file_000.txt.sb0nji)은 HoldFS 기록에 원래 이름(file_000.txt)으로 남으므로,
// 그대로 찾지 못하면 마지막 확장자를 뗀 이름으로 한 번 더 찾는다.
export function targetFor(events: EdrEvent[], root: string, rel: string): string {
  const find = (r: string) => events.find((e) => e.target && !e.target.includes(" → ") && sameFile(e.target, r));
  const base = rel.replace(/(\.[^./]+)\.[^./]+$/, "$1");
  const hit = find(rel) ?? (base !== rel ? find(base) : undefined);
  return hit ? hit.target : `${root.replace(/\/$/, "")}/${rel}`;
}

export const isHoneypotBlock = (e: EdrEvent) => e.result === "BLOCKED" && /honeypot/i.test(e.reason || "");

// ── 보류 중인 쓰기 (MEDIUM 대기열) ──────────────────────────────────────────
// HoldFS는 MEDIUM 프로세스의 쓰기를 원본에 바로 반영하지 않고 잡아 둔다(WRITE/SETATTR … BUFFERED).
// 다음 중 하나가 오면 그 PID의 보류 쓰기는 끝난 것으로 본다.
//   COMMIT … : 관찰 시간 종료 후 원본에 반영
//   DROP / BUFFER_DROPPED, HIGH : 버려지고 원본 보존
//   RETURN(LOW) : 정상 판정으로 복귀
// 남은 시간 = MEDIUM 진입 시각 + MEDIUM 관찰 시간(config.STAGE2_MEDIUM_TIMEOUT_SEC) - 지금

// 끝났다는 이벤트를 놓친 PID가 계속 남지 않도록, 반영 예정 시각에서 이만큼 지나면 목록에서 뺀다.
const STALE_SEC = 60;

export interface PendingRow {
  pid: number;
  process: string;
  files: string[];       // 보류된 대상 파일 (처음 나온 순서)
  writes: number;        // 보류된 작업 수
  since: number;         // MEDIUM 진입(없으면 첫 보류) 시각 ms
  dyn: string | null;    // 마지막 동적 모델 점수
}

const isDone = (e: EdrEvent) =>
  e.action === "COMMIT" || e.action === "DROP" || e.action === "RETURN" ||
  e.result === "BUFFER_DROPPED" || e.level === "HIGH";

export function pendingWrites(events: EdrEvent[], timeoutSec: number, now: number): PendingRow[] {
  const byPid = new Map<number, EdrEvent[]>();
  for (const e of events) {
    const list = byPid.get(e.pid);
    if (list) list.push(e); else byPid.set(e.pid, [e]);
  }
  const rows: PendingRow[] = [];
  for (const [pid, list] of byPid) {
    const sorted = [...list].sort((a, b) => a.time.localeCompare(b.time));
    let lastDone = -1;
    sorted.forEach((e, i) => { if (isDone(e)) lastDone = i; });
    let open = sorted.slice(lastDone + 1);
    // MEDIUM 진입 기록이 있으면 마지막 진입부터, 없으면(선제 MEDIUM 등) 최근 보류만 본다
    const enterIdx = open.map((e) => e.action === "ESCALATE" && e.result === "MEDIUM").lastIndexOf(true);
    if (enterIdx >= 0) open = open.slice(enterIdx);
    else open = open.filter((e) => now - eventMs(e.time) <= (timeoutSec + STALE_SEC) * 1000);
    const buffered = open.filter((e) => e.result === "BUFFERED");
    if (!buffered.length) continue;
    const since = eventMs((enterIdx >= 0 ? open[0] : buffered[0]).time);
    if (now > since + (timeoutSec + STALE_SEC) * 1000) continue;
    const files: string[] = [];
    for (const e of buffered) if (e.target && !files.includes(e.target)) files.push(e.target);
    const scored = [...sorted].reverse().find((e) => /dyn=[\d.]+/.test(e.reason || ""));
    rows.push({
      pid,
      process: [...open].reverse().find((e) => e.process && e.process !== "-")?.process ?? "-",
      files,
      writes: buffered.length,
      since,
      dyn: scored ? scored.reason.match(/dyn=([\d.]+)/)![1] : null,
    });
  }
  return rows.sort((a, b) => a.since - b.since);
}
