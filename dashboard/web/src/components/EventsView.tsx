import { useMemo, useState } from "react";

import { byPid, buckets, inPeriod, isLowWrite, periodStart, PERIODS, shownEvents, type Period } from "../eventStats";
import type { EdrEvent } from "../types";
import EventChart from "./EventChart";
import FileDetail from "./FileDetail";
import PidDetail from "./PidDetail";
import PidLog from "./PidLog";
import RunLog, { useRuns } from "./RunLog";


interface Props {
  events: EdrEvent[];
  onAskAi?: (pid: number) => void;
  initialPid?: number | null;   // 주소의 ?pid= 로 열었을 때 처음 보여줄 PID 상세
  onRun?: (name: string) => void;  // 실행별 로그 조회 '상세 보기' → 파일 현황 › 실행별 상세
}

// 값이 있으면 목록 대신 그 PID 또는 파일의 상세 화면을 보여준다
type Detail = { kind: "pid"; pid: number } | { kind: "file"; target: string } | null;

export default function EventsView({ events, onAskAi, initialPid = null, onRun }: Props) {
  const [period, setPeriod] = useState<Period>("1h");
  const [detail, setDetail] = useState<Detail>(
    initialPid !== null ? { kind: "pid", pid: initialPid } : null);
  // 그래프·목록이 같은 기록을 세도록 화면에 보여줄 기록만 남긴다 (상세 화면과 같은 기준)
  const scoped = useMemo(() => shownEvents(inPeriod(events, period)), [events, period]);
  // LOW 쓰기 반영 기록은 위협 이벤트가 아니므로 그래프에서는 뺀다 (PID 목록·상세에는 남긴다)
  const threats = useMemo(() => scoped.filter((e) => !isLowWrite(e)), [scoped]);
  const runList = useRuns(detail === null);

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
        <EventChart data={buckets(threats, periodStart(period))} />
        <div className="chart-foot">
          <p className="caption"><span style={{ color: "#c00000" }}>●</span> HIGH 격상 시점</p>
          <p className="caption blocked-count">차단 프로세스 수 <b>{blockedPids}</b>개</p>
        </div>
      </fieldset>

      <div className="grid2">
        <PidLog rows={byPid(scoped)} onDetail={showPid} />
        <RunLog runs={runList.runs} error={runList.error} onDetail={(name) => onRun?.(name)} />
      </div>
    </>
  );
}
