import { Fragment, useState } from "react";

import type { EdrEvent, EventStats } from "../types";

type Filter = "ALL" | "HIGH" | "MEDIUM" | "ESCALATE" | "HONEYPOT";

const FILTERS: [Filter, string][] = [
  ["ALL", "전체"], ["HIGH", "HIGH"], ["MEDIUM", "MEDIUM"], ["ESCALATE", "격상 이력"], ["HONEYPOT", "허니팟"],
];

function matchFilter(filter: Filter, e: EdrEvent) {
  if (filter === "ALL") return true;
  if (filter === "HONEYPOT") return /honeypot/i.test(e.reason || "");
  if (filter === "ESCALATE") return ["ESCALATE", "SIGSTOP", "RETURN"].includes(e.action) || e.result === "ESCALATED_TO_HIGH";
  return e.level === filter;
}

// 긴 경로가 '/' 뒤에서 줄바꿈되도록 <wbr>을 넣는다.
function BreakablePath({ path }: { path: string }) {
  const parts = path.split("/");
  return <>{parts.map((p, i) => (
    <Fragment key={i}>{p}{i < parts.length - 1 && <>/<wbr /></>}</Fragment>
  ))}</>;
}

interface Props {
  hidden: boolean;
  events: EdrEvent[];
  stats: EventStats;
  newIds: Set<number>;
  onFilterChange: () => void;
  onPidClick: (pid: number) => void;
}

export default function EventsView({ hidden, events, stats, newIds, onFilterChange, onPidClick }: Props) {
  const [filter, setFilter] = useState<Filter>("ALL");
  const rows = events.filter((e) => matchFilter(filter, e)).reverse();

  return (
    <div className="view" id="view-events" hidden={hidden}>
      <div className="stats">
        <div className="card card-total">
          <div className="card-icon">📋</div>
          <div className="card-body"><div className="num" id="stat-total">{stats.total}</div><div className="lbl">전체 이벤트</div></div>
        </div>
        <div className="card card-high">
          <div className="card-icon">🚨</div>
          <div className="card-body"><div className="num" id="stat-high">{stats.high}</div><div className="lbl">HIGH 위협</div></div>
        </div>
        <div className="card card-medium">
          <div className="card-icon">⚠️</div>
          <div className="card-body"><div className="num" id="stat-medium">{stats.medium}</div><div className="lbl">MEDIUM 의심</div></div>
        </div>
        <div className="card card-low">
          <div className="card-icon">🛡️</div>
          <div className="card-body"><div className="num" id="stat-blocked">{stats.blocked}</div><div className="lbl">차단된 작업</div></div>
        </div>
      </div>

      <section className="section" id="table-anchor">
        <div className="section-head">
          <h2>보안 이벤트 로그</h2>
          <div className="section-tools">
            {FILTERS.map(([key, label]) => (
              <button key={key} className={`filter-btn${filter === key ? " active" : ""}`} data-filter={key}
                onClick={() => { setFilter(key); onFilterChange(); }}>{label}</button>
            ))}
            <span id="event-count">{rows.length}개 이벤트</span>
          </div>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>시각</th><th>위험도</th><th>PID</th><th>프로세스</th>
                <th>대상 파일</th><th>동작</th><th>결과</th><th>탐지 사유</th>
              </tr>
            </thead>
            <tbody id="event-body">
              {rows.length === 0 ? (
                <tr><td colSpan={8} className="empty">
                  {events.length ? "필터에 해당하는 이벤트가 없습니다." : <>
                    수신된 이벤트가 없습니다.<br /><br />
                    에이전트 실행: <code>python dashboard/agent.py</code> &nbsp;·&nbsp; 샘플: <code>python dashboard/agent.py --demo</code>
                  </>}
                </td></tr>
              ) : rows.slice(0, 500).map((e) => (
                <tr key={e.id} className={`lv-${e.level}${newIds.has(e.id) ? " new" : ""}`}>
                  <td className="time">{e.time}</td>
                  <td><span className={`badge badge-${e.level}`}>{e.level}</span></td>
                  <td><span className="pid-link" data-pid={e.pid} title="AI 분석관에게 이 PID 분석 요청"
                    onClick={() => onPidClick(e.pid)}>{e.pid}</span></td>
                  <td className="proc">{e.process || "-"}</td>
                  <td className="target"><BreakablePath path={e.target} /></td>
                  <td><span className="action">{e.action}</span></td>
                  <td className={`result res-${e.result}`}>{e.result}</td>
                  <td className="reason">{e.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
