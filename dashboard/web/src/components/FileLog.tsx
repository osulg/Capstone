import { useState } from "react";

import type { FileRow } from "../eventStats";

interface Props {
  rows: FileRow[];
  onDetail: (target: string) => void;
}

export default function FileLog({ rows, onDetail }: Props) {
  const [query, setQuery] = useState("");
  const [applied, setApplied] = useState("");
  const q = applied.trim().toLowerCase();
  const shown = q ? rows.filter((r) => r.target.toLowerCase().includes(q)) : rows;

  return (
    <fieldset>
      <legend>파일별 로그 조회</legend>
      <div className="row-line">
        <label className="field">파일:
          <input type="text" size={18} placeholder="파일 이름 또는 경로" value={query}
            onChange={(e) => setQuery(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") setApplied(query); }} />
        </label>
        <button className="btn" onClick={() => setApplied(query)}>검색</button>
      </div>
      <div className="list">
        <table>
          <thead><tr><th>파일</th><th>시각</th><th>결과</th><th>상세</th></tr></thead>
          <tbody>
            {shown.map((r) => (
              <tr key={r.target} title={r.target}>
                <td className="mono wrap">{r.short}</td>
                <td className="mono">{r.time.slice(11)}</td>
                <td className={r.danger ? "high" : ""}>{r.result}</td>
                <td>
                  <button className="link-btn" onClick={() => onDetail(r.target)}>상세 보기 ›</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="count-line">파일 {rows.length}개 중 {shown.length}개 표시</div>
    </fieldset>
  );
}