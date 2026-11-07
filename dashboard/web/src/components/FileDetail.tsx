import { droppedPids, fileResult, LEVEL_RANK, shortPath } from "../eventStats";
import type { EdrEvent } from "../types";

interface Props {
  target: string;
  events: EdrEvent[];          // 조회 기간과 상관없이 전체 이벤트에서 이 파일 것만 쓴다
  onBack: () => void;
  onPid: (pid: number) => void; // 접근한 프로세스의 PID 상세로 이동
}

const hms = (t: string) => t.slice(11);

interface Accessor {
  pid: number;
  process: string;
  level: string;
  count: number;
  result: string;   // 이 파일에 대한 마지막 결과
  last: string;
}

export default function FileDetail({ target, events, onBack, onPid }: Props) {
  const dropped = droppedPids(events);
  const rows = events.filter((e) => e.target === target).sort((a, b) => a.time.localeCompare(b.time));
  const last = rows[rows.length - 1];

  // 이 파일에 접근한 프로세스별로 묶는다 (위험도 높은 순)
  const map = new Map<number, Accessor>();
  for (const e of rows) {
    const a = map.get(e.pid) ?? { pid: e.pid, process: e.process, level: "LOW", count: 0, result: "", last: "" };
    a.count += 1;
    if ((LEVEL_RANK[e.level] ?? 0) > (LEVEL_RANK[a.level] ?? 0)) a.level = e.level;
    a.result = fileResult(e, dropped);
    a.last = e.time;
    map.set(e.pid, a);
  }
  const accessors = [...map.values()].sort((a, b) =>
    (LEVEL_RANK[b.level] ?? 0) - (LEVEL_RANK[a.level] ?? 0) || b.last.localeCompare(a.last));
  const state = last ? fileResult(last, dropped) : "-";
  const danger = (s: string) => (s === "차단" || s === "미끼 접근" ? "high" : "");

  return (
    <>
      <fieldset>
        <legend>파일 상세 · {shortPath(target)}</legend>
        <div className="row-line">
          <button className="btn" onClick={onBack}>‹ 목록으로</button>
          <span className="mono hint" title={target}>{target}</span>
        </div>
        {rows.length === 0 ? (
          <div className="empty" style={{ height: 120 }}>이 파일의 이벤트가 없습니다.</div>
        ) : (
          <table className="detail-summary">
            <tbody>
              <tr>
                <th>현재 상태</th><th className="num">접근한 프로세스</th><th className="num">이벤트</th>
                <th>첫 이벤트</th><th>마지막 이벤트</th>
              </tr>
              <tr>
                <td className={danger(state)}>{state}</td>
                <td className="num">{accessors.length}개</td>
                <td className="num">{rows.length}건</td>
                <td className="mono">{hms(rows[0].time)}</td>
                <td className="mono">{hms(last.time)}</td>
              </tr>
            </tbody>
          </table>
        )}
      </fieldset>

      {rows.length > 0 && <>
        <fieldset>
          <legend>접근한 프로세스</legend>
          <div className="list" style={{ height: "auto", maxHeight: 220 }}>
            <table>
              <thead><tr><th>PID</th><th>프로세스</th><th>최고 위험도</th><th className="num">이 파일 작업</th><th>결과</th><th>상세</th></tr></thead>
              <tbody>
                {accessors.map((a) => (
                  <tr key={a.pid}>
                    <td className="mono">{a.pid}</td>
                    <td>{a.process}</td>
                    <td className={a.level === "HIGH" ? "high" : ""}>{a.level}</td>
                    <td className="num">{a.count}건</td>
                    <td className={danger(a.result)}>{a.result}</td>
                    <td><button className="link-btn" onClick={() => onPid(a.pid)}>PID 상세 ›</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </fieldset>

        <fieldset>
          <legend>파일 이력 ({rows.length}건)</legend>
          <div className="list" style={{ height: 320 }}>
            <table>
              <thead><tr><th>시각</th><th>프로세스</th><th>위험도</th><th>동작</th><th>결과</th><th>사유</th></tr></thead>
              <tbody>
                {rows.map((e) => (
                  <tr key={e.id}>
                    <td className="mono">{hms(e.time)}</td>
                    <td>{e.process} ({e.pid})</td>
                    <td className={e.level === "HIGH" ? "high" : ""}>{e.level}</td>
                    <td>{e.action}</td>
                    <td className={danger(fileResult(e, dropped))}>{fileResult(e, dropped)}</td>
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
