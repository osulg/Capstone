import { useEffect, useState } from "react";

import { fetchRun } from "../api";
import { fmtTime, hhmmss, targetFor } from "../fileStats";
import type { EdrEvent, FileInfo, RunDetailResponse } from "../types";

const RUN_POLL_MS = 2000;

interface Props {
  name: string;
  events: EdrEvent[];
  onBack: () => void;
  onFile: (target: string, file: FileInfo) => void;   // 파일 상세 (이벤트 경로 + 지금 파일 상태)
}

// 파일 현황 › 실행별 상세: 실행 폴더 하나의 보호 결과 요약과 파일 전체 목록
export default function RunDetail({ name, events, onBack, onFile }: Props) {
  const [data, setData] = useState<RunDetailResponse | null | undefined>(undefined);
  const [updated, setUpdated] = useState("불러오는 중…");

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const d = await fetchRun(name);
        if (!alive) return;
        setData(d);
        setUpdated(hhmmss(new Date()) + " 갱신");
      } catch {
        if (alive) setUpdated("서버 연결 끊김");
      }
    };
    tick();
    const timer = setInterval(tick, RUN_POLL_MS);
    return () => { alive = false; clearInterval(timer); };
  }, [name]);

  const s = data?.summary;
  const files = data?.files ?? [];
  const other = s ? s.total - s.suspect - s.ok : 0;   // 읽기 실패·판정 불가
  const threshold = (data?.threshold ?? 7).toFixed(1);

  return (
    <>
      <p className="crumb">파일 현황 › 실행별 상세 › <b>{name}</b><span>{updated}</span></p>
      <div className="row-line" style={{ marginBottom: 10 }}>
        <button className="btn" onClick={onBack}>‹ 실행 목록으로</button>
      </div>

      {data === null ? (
        <div className="empty" style={{ height: 160 }}>실행 폴더가 없습니다. 이미 지워졌을 수 있습니다.</div>
      ) : <>
        <fieldset>
          <legend>보호 결과 요약</legend>
          <div className="result-grid single">
            <div className="result-box">
              <div className="result-title">{s ? `${s.label} · ${name}` : name} (HoldFS 보호 폴더 · underlay)</div>
              {!s ? <div className="result-empty">불러오는 중…</div>
                : s.total === 0 ? <div className="result-empty">파일이 없습니다.</div>
                : <>
                  <div className="result-num">
                    <b className={s.suspect > 0 ? "bad" : ""}>{s.suspect}</b><span> / {s.total}</span>
                  </div>
                  <div className="result-label">감염 의심</div>
                  <div className="result-sub">원본 유지 {s.ok}{other > 0 && <> · 판정 불가 {other}</>}</div>
                </>}
            </div>
          </div>
          <p className="caption" style={{ margin: "10px 0 0" }}>
            이 실행 폴더의 파일만 집계 · 2초마다 갱신 · 판정 기준 엔트로피 {threshold} 이상 (확장자 변경은 세지 않음)
          </p>
        </fieldset>

        <fieldset>
          <legend>{name} · underlay</legend>
          {!data ? <div className="empty" style={{ height: 120 }}>불러오는 중…</div>
            : files.length === 0 ? <div className="empty" style={{ height: 120 }}>파일이 없습니다.</div>
            : (
              <div className="list" style={{ height: "auto", maxHeight: "none" }}>
                <table>
                  <thead><tr><th>파일</th><th>상태</th><th className="num">엔트로피</th><th>수정</th><th>상세</th></tr></thead>
                  <tbody>
                    {files.map((f) => {
                      const bad = f.state === "encrypted";
                      const label = bad ? "암호화 의심" : f.state === "ok" ? "정상" : f.state === "unreadable" ? "읽기 실패" : "판정 불가";
                      return (
                        <tr key={f.path}>
                          <td className="mono" title={f.path}>{f.dir.includes("/") ? f.path.slice(name.length + 1) : f.name}</td>
                          <td className={bad ? "high" : ""}>{label}</td>
                          <td className={`num${bad ? " high" : ""}`}>{f.entropy == null ? "-" : f.entropy.toFixed(2)}</td>
                          <td className="mono">{fmtTime(f.mtime)}</td>
                          <td>
                            <button className="link-btn" onClick={() => onFile(targetFor(events, data.root, f.path), f)}>
                              상세 ›
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
                {data.truncated && <p className="caption" style={{ margin: 6 }}>파일이 많아 일부만 표시합니다.</p>}
              </div>
            )}
        </fieldset>
      </>}
    </>
  );
}
