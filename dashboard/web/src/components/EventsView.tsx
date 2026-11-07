import { useMemo, useState } from "react";

import { byFile, byPid, buckets, inPeriod, periodStart, PERIODS, type Period } from "../eventStats";
import type { EdrEvent } from "../types";
import EventChart from "./EventChart";
import FileDetail from "./FileDetail";
import FileLog from "./FileLog";
import PidDetail from "./PidDetail";
import PidLog from "./PidLog";


interface Props {
  events: EdrEvent[];
  onAskAi?: (pid: number) => void;
}

// 값이 있으면 목록 대신 그 PID 또는 파일의 상세 화면을 보여준다
type Detail = { kind: "pid"; pid: number } | { kind: "file"; target: string } | null;

export default function EventsView({ events, onAskAi }: Props) {
  const [period, setPeriod] = useState<Period>("1h");
  const [detail, setDetail] = useState<Detail>(null);
  const scoped = useMemo(() => inPeriod(events, period), [events, period]);

  // 차단 작업이 수행된 프로세스: 쓰기·이름 변경 등이 차단됐거나(BLOCKED) HIGH로 정지된 PID
  const blockedPids = new Set(scoped
    .filter((e) => e.result === "BLOCKED" || e.result === "SUSPENDED" || e.level === "HIGH")
    .map((e) => e.pid)).size;

  const showPid = (pid: number) => setDetail({ kind: "pid", pid });
  const showFile = (target: string) => setDetail({ kind: "file", target });

  if (detail?.kind === "pid") {
    return <PidDetail pid={detail.pid} events={events} onBack={() => setDetail(null)}
      onFile={showFile} onAskAi={onAskAi} />;
  }
  if (detail?.kind === "file") {
    return <FileDetail target={detail.target} events={events} onBack={() => setDetail(null)} onPid={showPid} />;
  }

  return (
    <>
      <fieldset>
        <legend>보안 위협 이벤트 조회</legend>
        <div className="row-line">
          <label className="field">조회 기간:
            <select value={period} onChange={(e) => setPeriod(e.target.value as Period)}>
              {PERIODS.map(([k, label]) => <option key={k} value={k}>{label}</option>)}
            </select>
          </label>
        </div>

        <p className="caption" style={{ margin: "12px 0 6px" }}>시간별 보안 위협 이벤트 수 </p>
        <EventChart data={buckets(scoped, periodStart(period))} />
        <div className="chart-foot">
          <p className="caption"><span style={{ color: "#c00000" }}>●</span> HIGH 격상 시점</p>
          <p className="caption blocked-count">차단 프로세스 수 <b>{blockedPids}</b>개</p>
        </div>
      </fieldset>

      <div className="grid2">
        <PidLog rows={byPid(scoped)} onDetail={showPid} />
        <FileLog rows={byFile(scoped)} onDetail={showFile} />
      </div>
    </>
  );
}
