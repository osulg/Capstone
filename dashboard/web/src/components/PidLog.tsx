import { useState } from "react";

import type { PidRow } from "../eventStats";

interface Props {
  rows: PidRow[];
  onDetail: (pid: number) => void;
}

// 상태 필터: 그 PID 가 도달한 최고 위험도 기준
const LEVEL_FILTERS: [string, string][] = [
  ["ALL", "전체"], ["HIGH", "HIGH"], ["MEDIUM", "MEDIUM"], ["SUSPICIOUS", "SUSPICIOUS"], ["LOW", "LOW"],
];

export default function PidLog({ rows, onDetail }: Props) {
  const [query, setQuery] = useState("");
  const [applied, setApplied] = useState("");
  const [level, setLevel] = useState("ALL");
  const [selected, setSelected] = useState<number | null>(null);
  const q = applied.trim().toLowerCase();
  const shown = rows.filter((r) =>
    (level === "ALL" || r.level === level) &&
    (!q || String(r.pid).includes(q) || r.process.toLowerCase().includes(q)));

  return (
    <fieldset>
      <legend>PID별 로그 조회</legend>
      <div className="row-line">
        <label className="field">PID:
          <input type="text" size={12} placeholder="예: 905425" value={query}
            onChange={(e) => setQuery(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") setApplied(query); }} />
        </label>
        <button className="btn" onClick={() => setApplied(query)}>검색</button>
        <label className="field">상태:
          <select value={level} onChange={(e) => setLevel(e.target.value)} aria-label="상태 필터">
            {LEVEL_FILTERS.map(([k, label]) => <option key={k} value={k}>{label}</option>)}
          </select>
        </label>
      </div>
      <div className="list">
        <table>
          <thead><tr><th>PID</th><th>프로세스</th><th>상태</th><th className="num">이벤트</th><th>상세</th></tr></thead>
          <tbody>
            {shown.map((r) => (
              <tr key={r.pid} className={selected === r.pid ? "sel" : ""}
                onClick={() => setSelected(r.pid)}>
                <td className="mono">{r.pid}</td>
                <td title={r.comm ? `실행 파일: ${r.comm}` : undefined}>{r.process}</td>
                <td className={r.level === "HIGH" ? "high" : ""}>{r.level}</td>
                <td className="num">{r.count}</td>
                <td>
                  <button className="link-btn" onClick={(e) => { e.stopPropagation(); onDetail(r.pid); }}>
                    상세 보기 ›
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="count-line">프로세스 {rows.length}개 중 {shown.length}개 표시</div>
    </fieldset>
  );
}
