import { useEffect, useState } from "react";

import { fetchFiles } from "../api";
import { hhmmss } from "../fileStats";
import type { EdrEvent, FileInfo, FilesResponse } from "../types";
import FileDetail from "./FileDetail";
import HoneypotView from "./HoneypotView";
import PidDetail from "./PidDetail";
import RunDetail from "./RunDetail";
import RunLog, { useRuns } from "./RunLog";
import { FILES_SUBS, type FilesSub } from "./Tabs";

const FILE_POLL_MS = 2000;

interface Props {
  visible: boolean;
  sub: FilesSub;
  events: EdrEvent[];
  onAskAi?: (pid: number) => void;
  run: string | null;                       // 실행별 상세에서 연 실행 폴더 (없으면 실행 목록)
  onRun: (name: string | null) => void;
}

// 값이 있으면 목록 대신 그 PID 또는 파일의 상세 화면을 보여준다
type Detail = { kind: "pid"; pid: number } | { kind: "file"; target: string; file?: FileInfo } | null;

export default function FilesView({ visible, sub, events, onAskAi, run, onRun }: Props) {
  const [data, setData] = useState<FilesResponse | null>(null);
  const [updated, setUpdated] = useState("불러오는 중…");
  const [detail, setDetail] = useState<Detail>(null);

  // 하위 메뉴·실행 폴더를 바꾸면 상세 화면을 닫는다
  useEffect(() => setDetail(null), [sub, visible, run]);
  const runList = useRuns(visible && sub === "runs" && run === null);

  // 미끼 파일 상태 화면이 보일 때만 2초마다 폴더를 스캔한다.
  useEffect(() => {
    if (!visible || sub !== "honeypot") return;
    let alive = true;
    const tick = async () => {
      try {
        const d = await fetchFiles();
        if (!alive) return;
        setData(d);
        setUpdated(hhmmss(new Date()) + " 갱신");
      } catch {
        if (alive) setUpdated("서버 연결 끊김");
      }
    };
    tick();
    const timer = setInterval(tick, FILE_POLL_MS);
    return () => { alive = false; clearInterval(timer); };
  }, [visible, sub]);

  if (!visible) return null;

  const showPid = (pid: number) => setDetail({ kind: "pid", pid });
  const showFile = (target: string, file?: FileInfo) => setDetail({ kind: "file", target, file });
  if (detail?.kind === "pid") {
    return <PidDetail pid={detail.pid} events={events} onBack={() => setDetail(null)}
      onFile={showFile} onAskAi={onAskAi} />;
  }
  if (detail?.kind === "file") {
    return <FileDetail target={detail.target} file={detail.file} events={events}
      onBack={() => setDetail(null)} onPid={showPid} />;
  }

  if (sub === "runs" && run !== null) {
    return <RunDetail name={run} events={events} onBack={() => onRun(null)} onFile={showFile} />;
  }

  const label = FILES_SUBS.find(([k]) => k === sub)?.[1];
  return (
    <>
      <p className="crumb">파일 현황 › <b>{label}</b>{sub === "honeypot" && <span>{updated}</span>}</p>
      {sub === "runs" && <RunLog runs={runList.runs} error={runList.error} onDetail={onRun} tall />}
      {sub === "honeypot" && <HoneypotView data={data} events={events} onFile={showFile} onPid={showPid} />}
    </>
  );
}
