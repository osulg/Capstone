import { useEffect, useState } from "react";

import { shortPath } from "../eventStats";
import { pendingWrites } from "../fileStats";
import type { EdrEvent } from "../types";

// underlay 기준 상대 경로. 그래도 절대 경로면 마지막 두 단계만 보인다 (전체 경로는 마우스를 올리면 보임)
const short = (p: string) => {
  const s = shortPath(p);
  return s.startsWith("/") ? s.split("/").slice(-2).join("/") : s;
};

interface Props {
  events: EdrEvent[];
  timeoutSec: number;          // MEDIUM 관찰 시간 (config.STAGE2_MEDIUM_TIMEOUT_SEC)
  onPid: (pid: number) => void;
}

export default function PendingView({ events, timeoutSec, onPid }: Props) {
  // 남은 시간 표시를 위해 1초마다 다시 그린다
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  const rows = pendingWrites(events, timeoutSec, now);

  return (
    <fieldset>
      <legend>보류 중인 쓰기 (MEDIUM 대기열)</legend>
      {rows.length === 0 ? (
        <div className="empty" style={{ height: 120 }}>지금 보류 중인 쓰기가 없습니다.</div>
      ) : (
        <div className="list" style={{ height: "auto" }}>
          <table>
            <thead><tr><th>PID</th><th>프로세스</th><th>파일</th><th className="num">보류 쓰기</th><th>판정</th><th>상세</th></tr></thead>
            <tbody>
              {rows.map((r) => {
                const left = Math.ceil((r.since + timeoutSec * 1000 - now) / 1000);
                return (
                  <tr key={r.pid}>
                    <td className="mono">{r.pid}</td>
                    <td>{r.process}</td>
                    <td className="mono" title={r.files.join("\n")}>
                      {r.files.length ? short(r.files[0]) : "-"}{r.files.length > 1 && ` 외 ${r.files.length - 1}개`}
                    </td>
                    <td className="num">{r.writes}건</td>
                    <td>
                      <b>{left > 0 ? `재평가 중 · ${left}초 후 반영 예정` : "반영 대기"}</b>
                      {r.dyn && <span className="muted"> (dyn {Number(r.dyn).toFixed(2)})</span>}
                    </td>
                    <td><button className="link-btn" onClick={() => onPid(r.pid)}>PID 상세 ›</button></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <p className="caption" style={{ margin: "8px 0 0" }}>
        판정이 끝날 때까지 쓰기를 원본에 반영하지 않고 잡아 둡니다. HIGH로 판정되면 보류된 쓰기는 버려지고 원본이 그대로 남습니다.
      </p>
    </fieldset>
  );
}
