import { LEVEL_RANK, shortPath } from "../eventStats";
import type { EdrEvent } from "../types";

interface Props {
  pid: number;
  events: EdrEvent[];          // 조회 기간과 상관없이 전체 이벤트에서 이 PID 것만 쓴다
  onBack: () => void;
  onFile?: (target: string) => void;   // 대상 파일을 누르면 파일 상세로 이동
  onAskAi?: (pid: number) => void;
}

const hms = (t: string) => t.slice(11);

// 진행 흐름에 올릴 이벤트와 그 이름
function stepLabel(e: EdrEvent): string | null {
  if (e.action === "ESCALATE") return `${e.level} 격상`;
  if (e.action === "RETURN") return "정상 복귀 (LOW)";
  if (e.action === "SIGSTOP") return "프로세스 정지 (SIGSTOP)";
  if (e.action === "DETECT") return "Stage1 탐지";
  if (e.result === "BUFFER_DROPPED") return "보류 쓰기 폐기 · 원본 보존";
  if (e.action === "COMMIT" && e.result === "DATA_APPLIED") return "보류 쓰기 반영 (정상 판정)";
  if (e.action === "COMMIT" && (e.result === "APPLY_FAILED" || e.result === "IO_FAILED")) return "보류 쓰기 반영 실패";
  if (e.result === "BLOCKED" && /honeypot/i.test(e.reason || "")) return "허니팟 접근 차단";
  return null;
}

// 보류 쓰기를 원본에 반영한 결과 (HoldFS medium.py의 COMMIT 로그)
const APPLIED = new Set(["FILE_APPLIED", "DATA_APPLIED"]);
const APPLY_FAILED = new Set(["APPLY_FAILED", "IO_FAILED", "NOT_COMPLETED"]);

// 마지막으로 어떤 조치가 됐는지. 보류 쓰기가 반영됐는지 / 버려졌는지도 함께 보여준다.
function finalAction(rows: EdrEvent[]): string {
  const dropped = rows.some((e) => e.result === "BUFFER_DROPPED");
  const dropNote = dropped ? " · 보류 쓰기 폐기" : "";
  if (rows.some((e) => e.result === "SUSPENDED")) return "차단·정지됨" + dropNote;
  if (rows.some((e) => e.result === "BLOCKED")) return "작업 차단됨" + dropNote;
  if (dropped) return "보류 쓰기 폐기 · 원본 보존";

  // 마지막 보류 쓰기 이후에 반영 기록이 있는지 본다
  const lastBuf = rows.map((e) => e.result === "BUFFERED").lastIndexOf(true);
  const after = rows.slice(lastBuf + 1);
  if (lastBuf >= 0 && after.some((e) => e.action === "COMMIT" && APPLY_FAILED.has(e.result))) return "정상 판정 · 반영 실패";
  if (lastBuf >= 0 && after.some((e) => e.action === "COMMIT" && APPLIED.has(e.result))) return "정상 판정 · 쓰기 반영됨";

  const last = rows[rows.length - 1];
  if (last?.action === "RETURN") return "정상 복귀";
  if (rows.some((e) => e.level === "MEDIUM")) return "감시 중 (쓰기 보류)";
  return "관찰";
}

export default function PidDetail({ pid, events, onBack, onFile, onAskAi }: Props) {
  const rows = events.filter((e) => e.pid === pid).sort((a, b) => a.time.localeCompare(b.time));
  const process = [...rows].reverse().find((e) => e.process && e.process !== "-")?.process ?? "-";
  const level = rows.reduce((m, e) => ((LEVEL_RANK[e.level] ?? 0) > (LEVEL_RANK[m] ?? 0) ? e.level : m), "LOW");
  const files = new Set(rows.filter((e) => e.target).map((e) => e.target)).size;
  const steps = rows.map((e) => ({ e, label: stepLabel(e) })).filter((s) => s.label);
  if (rows.length && !steps.some((s) => s.e === rows[0])) steps.unshift({ e: rows[0], label: "첫 이벤트" });

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
                <td className={level === "HIGH" ? "high" : ""}>{finalAction(rows)}</td>
                <td className="mono">{hms(rows[0].time)}</td>
                <td className="mono">{hms(rows[rows.length - 1].time)}</td>
                <td className="num">{rows.length}건</td>
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
            {steps.map(({ e, label }) => (
              <li key={e.id} className={`lv-${e.level}`}>
                <span className="mono">{hms(e.time)}</span>
                <b>{label}</b>
                <span className="why">{e.reason}</span>
              </li>
            ))}
          </ol>
        </fieldset>

        <fieldset>
          <legend>전체 로그 ({rows.length}건)</legend>
          <div className="list" style={{ height: 320 }}>
            <table>
              <thead><tr><th>시각</th><th>위험도</th><th>동작</th><th>결과</th><th>대상 파일</th><th>사유</th></tr></thead>
              <tbody>
                {rows.map((e) => (
                  <tr key={e.id}>
                    <td className="mono">{hms(e.time)}</td>
                    <td className={e.level === "HIGH" ? "high" : ""}>{e.level}</td>
                    <td>{e.action}</td>
                    <td className={e.result === "BLOCKED" ? "high" : ""}>{e.result}</td>
                    <td className="mono" title={e.target}>
                      {!e.target ? "-" : onFile
                        ? <button className="link-btn mono" onClick={() => onFile(e.target)}>{shortPath(e.target)}</button>
                        : shortPath(e.target)}
                    </td>
                    <td className="why" title={e.reason}>{e.reason}</td>
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
