import { useState } from "react";

import type { PidRow } from "../eventStats";

interface Props {
  rows: PidRow[];
  onDetail: (pid: number) => void;
}

export default function PidLog({ rows, onDetail }: Props) {
  const [query, setQuery] = useState("");
  const [applied, setApplied] = useState("");
  const [selected, setSelected] = useState<number | null>(null);
  const q = applied.trim().toLowerCase();
  const shown = q ? rows.filter((r) => String(r.pid).includes(q) || r.process.toLowerCase().includes(q)) : rows;

  return (
    <fieldset>
      <legend>PID별 로그 조회</legend>
      <div className="row-line">
        <label className="field">PID:
          <input type="text" size={12} placeholder="예: 905425" value={query}
            onChange={(e) => setQuery(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") setApplied(query); }} />
        </label>
        <button className="btn" onClick={() => setApplied(query)}>검색</button>
      </div>
      <div className="list">
        <table>
          <thead><tr><th>PID</th><th>프로세스</th><th>상태</th><th className="num">이벤트</th><th>상세</th></tr></thead>
          <tbody>
            {shown.map((r) => (
              <tr key={r.pid} className={selected === r.pid ? "sel" : ""}
                onClick={() => setSelected(r.pid)}>
                <td className="mono">{r.pid}</td>
                <td>{r.process}</td>
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
