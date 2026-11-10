import { useEffect, useState } from "react";

import { fetchRuns } from "../api";
import { fmtTime } from "../fileStats";
import type { RunSummary } from "../types";

const RUN_POLL_MS = 2000;

// 긴 실행 폴더 이름을 목록에 맞게 줄인다: s04_71a43a3d…41b2eef → s04_71a43a…2eef
export const shortRun = (name: string) => `${name.slice(0, 10)}…${name.slice(-4)}`;

// 보일 때만 2초마다 실행 폴더 목록을 다시 읽는다
export function useRuns(visible: boolean) {
  const [runs, setRuns] = useState<RunSummary[] | null>(null);
  const [error, setError] = useState(false);
  useEffect(() => {
    if (!visible) return;
    let alive = true;
    const tick = async () => {
      try {
        const d = await fetchRuns();
        if (!alive) return;
        setRuns(d.runs);
        setError(false);
      } catch {
        if (alive) setError(true);
      }
    };
    tick();
    const timer = setInterval(tick, RUN_POLL_MS);
    return () => { alive = false; clearInterval(timer); };
  }, [visible]);
  return { runs, error };
}

interface Props {
  runs: RunSummary[] | null;
  error?: boolean;
  onDetail: (name: string) => void;
  title?: string;
  tall?: boolean;   // 파일 현황에서 목록만 보여줄 때 높이를 늘린다
}

export default function RunLog({ runs, error, onDetail, title = "실행별 로그 조회", tall }: Props) {
  const [query, setQuery] = useState("");
  const [applied, setApplied] = useState("");
  const q = applied.trim().toLowerCase();
  const all = runs ?? [];
  const shown = q
    ? all.filter((r) => r.name.includes(q) || r.label.toLowerCase().includes(q) || r.scenario.toLowerCase() === q)
    : all;

  return (
    <fieldset>
      <legend>{title}</legend>
      <div className="row-line">
        <label className="field">실행 폴더:
          <input type="text" size={18} placeholder="s04_… 또는 시나리오" value={query}
            onChange={(e) => setQuery(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") setApplied(query); }} />
        </label>
        <button className="btn" onClick={() => setApplied(query)}>검색</button>
      </div>
      <div className="list" style={tall ? { height: "auto", maxHeight: 520, minHeight: 210 } : undefined}>
        {runs === null ? (
          <div className="empty" style={{ border: 0, height: "100%" }}>{error ? "서버 연결 끊김" : "불러오는 중…"}</div>
        ) : all.length === 0 ? (
          <div className="empty" style={{ border: 0, height: "100%" }}>웹 시연에서 시나리오를 실행하면 실행 폴더가 여기에 나타납니다.</div>
        ) : (
          <table>
            <thead><tr><th>실행 폴더</th><th>시각</th><th>감염 의심 / 전체</th><th>상세</th></tr></thead>
            <tbody>
              {shown.map((r) => (
                <tr key={r.name} title={`${r.label} · ${r.name}`}>
                  <td className="mono"><b>{r.scenario}</b> {shortRun(r.name)}</td>
                  <td className="mono">{fmtTime(r.mtime)}</td>
                  <td><b className={r.suspect > 0 ? "high" : ""}>{r.suspect}</b> / {r.total}</td>
                  <td><button className="link-btn" onClick={() => onDetail(r.name)}>상세 보기 ›</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <div className="count-line">실행 {all.length}개 중 {shown.length}개 표시 · 감염 의심 = 엔트로피 기준 이상 파일</div>
    </fieldset>
  );
}
