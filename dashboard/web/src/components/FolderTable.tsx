import { fmtTime, targetFor } from "../fileStats";
import type { EdrEvent, Folder } from "../types";

interface Props {
  title: string;
  folder?: Folder;
  simTarget: string;
  events?: EdrEvent[];                 // 보호 폴더만: 파일 상세로 넘어갈 때 이벤트 경로를 찾는다
  onFile?: (target: string) => void;   // 없으면 상세 칸은 "-"
}

export default function FolderTable({ title, folder, simTarget, events = [], onFile }: Props) {
  // 미끼 파일은 '미끼 파일 상태' 화면에서 따로 보여준다
  const files = (folder?.files ?? []).filter((f) => !f.honeypot);

  let body;
  if (!folder) {
    body = <div className="empty" style={{ height: 120 }}>불러오는 중…</div>;
  } else if (!files.length) {
    body = (
      <div className="empty folder-hint">
        {folder.exists ? <>파일이 없습니다. 시뮬레이터를 실행해 보세요.<br />
          <code>{`python3 experiments/simulators/sim_highentropy.py ${simTarget} --keep`}</code></>
          : <>폴더가 없습니다.<br /><code>mkdir -p {folder.path}</code></>}
      </div>
    );
  } else {
    body = (
      <div className="list" style={{ height: "auto", maxHeight: 360 }}>
        <table>
          <thead><tr><th>파일</th><th>상태</th><th className="num">엔트로피</th><th>수정</th><th>상세</th></tr></thead>
          <tbody>
            {files.map((f) => {
              const bad = f.state === "encrypted";
              const label = bad ? "암호화 의심" : f.state === "ok" ? "정상" : f.state === "unreadable" ? "읽기 실패" : "판정 불가";
              return (
                <tr key={f.path}>
                  <td className="mono" title={f.path}>{f.name}</td>
                  <td className={bad ? "high" : ""}>{label}</td>
                  <td className={`num${bad ? " high" : ""}`}>{f.entropy == null ? "-" : f.entropy.toFixed(2)}</td>
                  <td className="mono">{fmtTime(f.mtime)}</td>
                  <td>{onFile && folder
                    ? <button className="link-btn" onClick={() => onFile(targetFor(events, folder.path, f.path))}>상세 ›</button>
                    : <span className="muted">-</span>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {folder.truncated && <p className="caption" style={{ margin: 6 }}>파일이 많아 일부만 표시합니다.</p>}
      </div>
    );
  }

  return (
    <fieldset>
      <legend>{title}</legend>
      {body}
    </fieldset>
  );
}
