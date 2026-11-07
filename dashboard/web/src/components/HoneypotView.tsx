import { fmtTime, isHoneypotBlock, sameFile, targetFor } from "../fileStats";
import type { EdrEvent, FilesResponse } from "../types";

interface Props {
  data: FilesResponse | null;
  events: EdrEvent[];
  onFile: (target: string) => void;
  onPid: (pid: number) => void;
}

export default function HoneypotView({ data, events, onFile, onPid }: Props) {
  const folder = data?.folders.find((f) => f.key === "protected");
  const files = (folder?.files ?? []).filter((f) => f.honeypot);
  const threshold = data?.threshold ?? 7;
  const blocks = events.filter(isHoneypotBlock);

  return (
    <fieldset>
      <legend>미끼 파일 (허니팟)</legend>
      {!folder ? (
        <div className="empty" style={{ height: 120 }}>불러오는 중…</div>
      ) : files.length === 0 ? (
        <div className="empty" style={{ height: 120 }}>미끼 파일이 없습니다. ({folder.path}/honeypot)</div>
      ) : (
        <div className="list" style={{ height: "auto" }}>
          <table>
            <thead><tr>
              <th>미끼 파일</th><th>상태</th><th>수정 시각</th><th className="num">접근 차단</th><th>마지막 접근 시도</th><th>상세</th>
            </tr></thead>
            <tbody>
              {files.map((f) => {
                const hits = blocks.filter((e) => sameFile(e.target, f.path))
                  .sort((a, b) => a.time.localeCompare(b.time));
                const last = hits[hits.length - 1];
                // 미끼 파일은 아무도 고치면 안 된다: 의심 확장자가 붙었거나 엔트로피가 기준 이상이면 변조 의심
                const tampered = f.ransom_ext || f.state === "unreadable" || (f.entropy != null && f.entropy >= threshold);
                return (
                  <tr key={f.path}>
                    <td className="mono">{f.path}</td>
                    <td className={tampered ? "high" : ""}>{tampered ? "변조 의심" : "정상"}</td>
                    <td className="mono">{fmtTime(f.mtime)}</td>
                    <td className={`num${hits.length ? " high" : ""}`}>{hits.length}회</td>
                    <td>{last
                      ? <>{last.time.slice(11)} · {last.process} (<button className="link-btn" onClick={() => onPid(last.pid)}>PID {last.pid}</button>) · {last.action}</>
                      : <span className="muted">없음</span>}</td>
                    <td><button className="link-btn" onClick={() => onFile(targetFor(events, folder.path, f.path))}>상세 ›</button></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <p className="caption" style={{ margin: "8px 0 0" }}>
        정상 사용자는 열 이유가 없는 파일입니다. 접근을 시도한 프로세스는 바로 차단하고 의심 대상으로 올립니다.
      </p>
    </fieldset>
  );
}
