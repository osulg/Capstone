import { eventDate, LEVEL_RANK, shortPath } from "../eventStats";
import {
  causeText, describeEvent, isHiddenEvent, isHighCause, rawText, setattrSources, useThresholds,
} from "../reasonText";
import type { EdrEvent } from "../types";

interface Props {
  pid: number;
  events: EdrEvent[];          // 조회 기간과 상관없이 전체 이벤트에서 이 PID 것만 쓴다
  onBack: () => void;
  onFile?: (target: string) => void;   // 대상 파일을 누르면 파일 상세로 이동
  onAskAi?: (pid: number) => void;
}

const hms = (t: string) => t.slice(11);

// 진행 흐름의 점 색: 초록 LOW / 노랑 MEDIUM / 빨강 HIGH / 흰색 판정 전(SUSPICIOUS). 글씨는 HIGH만 빨강.
type StepLevel = "LOW" | "MEDIUM" | "HIGH" | "PENDING";
interface Step { e: EdrEvent; label: string; level: StepLevel }

const levelOf = (e: EdrEvent): StepLevel =>
  e.level === "HIGH" || e.level === "MEDIUM" || e.level === "LOW" ? e.level : "PENDING";

// 같은 초에 찍힌 이벤트는 실제로 일어나는 순서로 놓는다.
// (로그 파일과 실행 출력에서 따로 오기 때문에 받은 순서가 뒤바뀔 수 있다)
function tieRank(e: EdrEvent): number {
  if (isHighCause(e)) return 0;                                  // 격상 원인
  if (e.action === "ESCALATE" || e.action === "RETURN") return 1; // 격상 / 정상 복귀
  if (e.action === "DROP" || e.action === "COMMIT") return 2;     // 보류 쓰기 폐기 / 반영
  if (e.result === "BLOCKED") return 3;                           // HIGH 이후 첫 차단
  if (e.action === "SIGSTOP") return 4;                           // 정지 (high.py: 차단 기록 직후 suspend)
  return 2;
}

// HIGH 격상 바로 앞(2초 이내)의 격상 원인 기록. 전체 로그에서는 HIGH 격상 줄에 합친다.
function causeOf(rows: EdrEvent[], i: number): EdrEvent | undefined {
  const t = eventDate(rows[i]).getTime();
  return rows.slice(0, i).reverse().find((c) => isHighCause(c) && t - eventDate(c).getTime() <= 2000);
}

// 진행 흐름에 넣지 않는 첫 이벤트를 부를 이름
function firstName(e: EdrEvent): string {
  if (e.action === "MKDIR") return "폴더 생성";
  if (e.result === "BUFFERED" && e.action === "SETATTR") return "권한 변경 보류";
  if (e.result === "BUFFERED") return "쓰기 보류";
  if (e.result === "STAGED") return "삭제 보관";
  return "감시 시작";
}

function buildSteps(rows: EdrEvent[]): Step[] {
  const steps: Step[] = [];
  for (const e of rows) {
    const step = (label: string, level: StepLevel) => steps.push({ e, label, level });
    if (e.action === "ESCALATE" && e.level === "HIGH") step("HIGH 격상", "HIGH");
    else if (e.action === "ESCALATE") step(`${e.level} 격상`, levelOf(e));
    else if (e.action === "RETURN") step("정상 복귀 (LOW)", "LOW");
    else if (e.action === "SIGSTOP") step("프로세스 정지 (SIGSTOP)", "HIGH");
    else if (e.action === "DETECT") step("Stage1 탐지", "PENDING");
    else if (e.result === "BUFFER_DROPPED") {
      // 0개면 버린 게 없으니 뺀다
      if (Number((e.reason || "").match(/버퍼 (\d+)개/)?.[1] ?? 1) > 0) step("보류 쓰기 폐기 · 원본 보존", "HIGH");
    } else if (e.action === "COMMIT" && e.result === "DATA_APPLIED") step("보류 쓰기 반영 (정상 판정)", "LOW");
    else if (e.action === "COMMIT" && (e.result === "APPLY_FAILED" || e.result === "IO_FAILED")) step("보류 쓰기 반영 실패", "MEDIUM");
    else if (e.result === "BLOCKED" && /honeypot/i.test(e.reason || "")) step("허니팟 접근 차단", levelOf(e));
  }
  if (rows.length && !steps.some((s) => s.e === rows[0])) {
    steps.unshift({ e: rows[0], label: firstName(rows[0]), level: levelOf(rows[0]) });
  }
  return steps;
}

// 보류 쓰기를 원본에 반영한 결과 (HoldFS medium.py의 COMMIT 로그)
const COMMITTED = new Set(["FILE_APPLIED", "DATA_APPLIED", "APPLY_FAILED", "IO_FAILED", "NOT_COMPLETED"]);

// 최종 조치: 정지 / 정상 복귀 / 보류 / 관찰
function finalAction(rows: EdrEvent[]): { text: string; high: boolean } {
  if (rows.some((e) => e.level === "HIGH")) return { text: "정지", high: true };
  // 마지막 보류 쓰기 이후에 반영 기록이 있거나, 마지막 상태 변화가 정상 복귀면 정상 복귀
  const lastBuf = rows.map((e) => e.result === "BUFFERED").lastIndexOf(true);
  const committed = lastBuf >= 0 && rows.slice(lastBuf + 1).some((e) => e.action === "COMMIT" && COMMITTED.has(e.result));
  const lastState = [...rows].reverse().find((e) => e.action === "RETURN" || e.action === "ESCALATE");
  if (committed || (lastState?.action === "RETURN" && lastBuf < rows.indexOf(lastState))) {
    return { text: "정상 복귀", high: false };
  }
  if (rows.some((e) => e.level === "MEDIUM")) return { text: "보류", high: false };
  return { text: "관찰", high: false };
}

interface LogRow { e: EdrEvent; action: string; detail: string; target: string; raw: string }

// 전체 로그: 동작·상세를 풀어 쓰고, 격상 원인 기록은 HIGH 격상 줄에 합친다
function buildLog(rows: EdrEvent[], th: ReturnType<typeof useThresholds>): LogRow[] {
  const setattr = setattrSources(rows);
  const merged = new Set<number>();
  const out: LogRow[] = [];
  rows.forEach((e, i) => {
    let d = describeEvent(e, th, setattr.get(e.id));
    let target = e.target;
    let raw = rawText(e);
    if (e.action === "ESCALATE" && e.level === "HIGH") {
      const cause = causeOf(rows, i);
      if (cause) {
        merged.add(cause.id);
        d = { action: "HIGH 격상", detail: causeText(cause) };
        target = cause.target;
        raw = `${rawText(cause)}\n${raw}`;
      }
    }
    out.push({ e, action: d.action, detail: d.detail, target, raw });
  });
  return out.filter((r) => !merged.has(r.e.id));
}

export default function PidDetail({ pid, events, onBack, onFile, onAskAi }: Props) {
  const th = useThresholds();
  const rows = events.filter((e) => e.pid === pid && !isHiddenEvent(e))
    .sort((a, b) => a.time.localeCompare(b.time) || tieRank(a) - tieRank(b));
  const process = [...rows].reverse().find((e) => e.process && e.process !== "-")?.process ?? "-";
  const level = rows.reduce((m, e) => ((LEVEL_RANK[e.level] ?? 0) > (LEVEL_RANK[m] ?? 0) ? e.level : m), "LOW");
  const files = new Set(rows.filter((e) => e.target).map((e) => e.target)).size;
  const steps = buildSteps(rows);
  const final = finalAction(rows);
  const log = buildLog(rows, th);

  return (
    <>
      <fieldset>
        <legend>PID 상세 · {pid}</legend>
        <div className="row-line">
          <button className="btn" onClick={onBack}>‹ 목록으로</button>
          {onAskAi && <button className="btn" onClick={() => onAskAi(pid)}>AI 분석관에게 이 PID 분석 요청</button>}
        </div>
        {rows.length === 0 ? (
          <div className="empty" style={{ height: 120 }}>이 PID의 이벤트가 없습니다.</div>
        ) : (
          <table className="detail-summary">
            <tbody>
              <tr>
                <th>프로세스</th><th>최고 위험도</th><th>최종 조치</th>
                <th>첫 이벤트</th><th>마지막 이벤트</th><th className="num">이벤트</th><th className="num">건드린 파일</th>
              </tr>
              <tr>
                <td>{process}</td>
                <td className={level === "HIGH" ? "high" : ""}>{level}</td>
                <td className={`final${final.high ? " high" : ""}`}>{final.text}</td>
                <td className="mono">{hms(rows[0].time)}</td>
                <td className="mono">{hms(rows[rows.length - 1].time)}</td>
                <td className="num">{log.length}건</td>
                <td className="num">{files}개</td>
              </tr>
            </tbody>
          </table>
        )}
      </fieldset>

      {rows.length > 0 && <>
        <fieldset>
          <legend>진행 흐름</legend>
          <ol className="pid-flow">
            {steps.map(({ e, label, level: lv }) => (
              <li key={`${e.id}-${label}`} className={`lv-${lv}`}>
                <span className="mono">{hms(e.time)}</span>
                <b>{label}</b>
              </li>
            ))}
          </ol>
        </fieldset>

        <fieldset>
          <legend>전체 로그 ({log.length}건)</legend>
          <div className="list" style={{ height: 320 }}>
            <table>
              <thead><tr><th>시각</th><th>위험도</th><th>동작</th><th>대상 파일</th><th>상세</th></tr></thead>
              <tbody>
                {log.map(({ e, action, detail, target, raw }) => (
                  <tr key={e.id} title={raw}>
                    <td className="mono">{hms(e.time)}</td>
                    <td className={e.level === "HIGH" ? "high" : ""}>{e.level}</td>
                    <td className={e.level === "HIGH" ? "high" : ""}>{action}</td>
                    <td className="mono">
                      {!target ? "-" : onFile
                        ? <button className="link-btn mono" onClick={() => onFile(target)}>{shortPath(target)}</button>
                        : shortPath(target)}
                    </td>
                    <td className="why">{detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </fieldset>
      </>}
    </>
  );
}
