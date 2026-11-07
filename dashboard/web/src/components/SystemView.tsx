import { useEffect, useState } from "react";

import { fetchHealth, fetchSystem } from "../api";
import { hhmmss, pendingWrites } from "../fileStats";
import { procSummary } from "../procStats";
import type { EdrEvent, SystemStatus } from "../types";
import FileDetail from "./FileDetail";
import PidDetail from "./PidDetail";

const SYSTEM_POLL_MS = 2000;
const DEFAULT_MEDIUM_TIMEOUT_SEC = 10;   // 서버가 config 값을 못 줄 때만 쓴다

interface Props {
  events: EdrEvent[];
  onAskAi?: (pid: number) => void;
}

type Detail = { kind: "pid"; pid: number } | { kind: "file"; target: string } | null;

function StatusBox({ title, ok, text }: { title: string; ok: boolean | undefined; text: string }) {
  return (
    <div className="sys-box">
      <div className="sys-title">{title}</div>
      <div className={`sys-val${ok === false ? " bad" : ""}`}>{ok === undefined ? "확인 중…" : text}</div>
    </div>
  );
}

export default function SystemView({ events, onAskAi }: Props) {
  const [sys, setSys] = useState<SystemStatus | null>(null);
  const [updated, setUpdated] = useState("불러오는 중…");
  const [now, setNow] = useState(() => new Date());
  const [detail, setDetail] = useState<Detail>(null);
  const [timeoutSec, setTimeoutSec] = useState(DEFAULT_MEDIUM_TIMEOUT_SEC);

  // MEDIUM 관찰 시간 (config.STAGE2_MEDIUM_TIMEOUT_SEC): 보류 쓰기가 반영되기까지 남은 시간 계산용
  useEffect(() => {
    fetchHealth().then((h) => { if (h.medium_timeout_sec) setTimeoutSec(h.medium_timeout_sec); }).catch(() => {});
  }, []);

  // 보류 쓰기 남은 시간 표시를 위해 1초마다 다시 그린다
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const s = await fetchSystem();
        if (!alive) return;
        setSys(s);
        setUpdated(hhmmss(new Date()) + " 갱신");
      } catch {
        if (alive) { setSys(null); setUpdated("서버 연결 끊김"); }
      }
    };
    tick();
    const timer = setInterval(tick, SYSTEM_POLL_MS);
    return () => { alive = false; clearInterval(timer); };
  }, []);

  const showPid = (pid: number) => setDetail({ kind: "pid", pid });
  if (detail?.kind === "pid") {
    return <PidDetail pid={detail.pid} events={events} onBack={() => setDetail(null)}
      onFile={(target) => setDetail({ kind: "file", target })} onAskAi={onAskAi} />;
  }
  if (detail?.kind === "file") {
    return <FileDetail target={detail.target} events={events} onBack={() => setDetail(null)} onPid={showPid} />;
  }

  const p = procSummary(events, now);
  // MEDIUM 프로세스가 원본에 반영하지 않고 잡아 둔 쓰기 (PID별)
  const pending = new Map(pendingWrites(events, timeoutSec, now.getTime()).map((w) => [w.pid, w]));
  const pendingText = (pid: number) => {
    const w = pending.get(pid);
    if (!w) return "-";
    const left = Math.ceil((w.since + timeoutSec * 1000 - now.getTime()) / 1000);
    return `${w.writes}건 · ${left > 0 ? `${left}초 후 반영` : "반영 대기"}`;
  };
  return (
    <>
      <p className="crumb">시스템 현황<span>{updated}</span></p>

      <fieldset>
        <legend>동작 상태</legend>
        <div className="sys-head">
          <b className={`sys-big${sys && !sys.protected ? " bad" : ""}`}>
            {!sys ? "확인 중…" : sys.protected ? "보호 중" : "보호 꺼짐"}
          </b>
        </div>
        <div className="sys-grid">
          <StatusBox title="HoldFS 프로세스" ok={sys?.holdfs.running} text={sys?.holdfs.running ? "실행 중" : "꺼짐"} />
          <StatusBox title="마운트" ok={sys?.mount.mounted} text={sys?.mount.mounted ? "마운트됨" : "마운트 안 됨"} />
          <StatusBox title="로그 수집 (agent)" ok={sys?.agent.running} text={sys?.agent.running ? "수집 중" : "꺼짐"} />
          {/* LLM이 없으면 로컬 규칙으로 답하므로 빨강으로 표시하지 않는다 */}
          <StatusBox title="AI 분석관" ok={sys ? true : undefined}
            text={sys?.llm.connected ? "LLM 연결됨" : "로컬 규칙 모드"} />
        </div>
      </fieldset>

      <fieldset>
        <legend>프로세스 상태 (오늘)</legend>
        <div className="num-grid">
          <div className="num-box"><div className="sys-title">감시 중 (MEDIUM)</div><b>{p.medium}</b></div>
          <div className="num-box"><div className="sys-title">차단·정지 (HIGH)</div><b className={p.high ? "bad" : ""}>{p.high}</b></div>
          <div className="num-box"><div className="sys-title">정상 복귀</div><b>{p.returned}</b></div>
          <div className="num-box"><div className="sys-title">허니팟 차단</div><b>{p.honeypot}</b></div>
        </div>
        {p.rows.length === 0 ? (
          <div className="empty" style={{ height: 90, marginTop: 12 }}>지금 감시 중이거나 차단된 프로세스가 없습니다.</div>
        ) : (
          <div className="list" style={{ height: "auto", maxHeight: 320, marginTop: 12 }}>
            <table>
              <thead><tr><th>PID</th><th>프로세스</th><th>상태</th><th>진입 시각</th><th>보류 쓰기</th><th>상세</th></tr></thead>
              <tbody>
                {p.rows.map((r) => {
                  const high = r.state === "HIGH";
                  return (
                    <tr key={r.pid}>
                      <td className="mono">{r.pid}</td>
                      <td>{r.process}</td>
                      <td className={high ? "high" : ""}>{high ? (r.suspended ? "HIGH · 정지됨" : "HIGH · 차단") : "MEDIUM · 감시 중"}</td>
                      <td className="mono">{r.since.slice(11)}</td>
                      <td title="원본에 반영하지 않고 잡아 둔 쓰기. HIGH가 되면 버려지고 원본이 보존된다">
                        {high ? "-" : pendingText(r.pid)}</td>
                      <td><button className="link-btn" onClick={() => showPid(r.pid)}>PID 상세 ›</button></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </fieldset>
    </>
  );
}
