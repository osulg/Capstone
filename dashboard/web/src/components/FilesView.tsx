import { useEffect, useState } from "react";

import { fetchFiles, fetchHealth } from "../api";
import { hhmmss } from "../fileStats";
import type { EdrEvent, FilesResponse } from "../types";
import CompareView from "./CompareView";
import FileDetail from "./FileDetail";
import HoneypotView from "./HoneypotView";
import PendingView from "./PendingView";
import PidDetail from "./PidDetail";
import { FILES_SUBS, type FilesSub } from "./Tabs";

const FILE_POLL_MS = 2000;
const DEFAULT_MEDIUM_TIMEOUT_SEC = 10;   // 서버가 config 값을 못 줄 때만 쓴다

interface Props {
  visible: boolean;
  sub: FilesSub;
  events: EdrEvent[];
  onAskAi?: (pid: number) => void;
}

// 값이 있으면 목록 대신 그 PID 또는 파일의 상세 화면을 보여준다
type Detail = { kind: "pid"; pid: number } | { kind: "file"; target: string } | null;

export default function FilesView({ visible, sub, events, onAskAi }: Props) {
  const [data, setData] = useState<FilesResponse | null>(null);
  const [updated, setUpdated] = useState("불러오는 중…");
  const [timeoutSec, setTimeoutSec] = useState(DEFAULT_MEDIUM_TIMEOUT_SEC);
  const [detail, setDetail] = useState<Detail>(null);

  // 하위 메뉴를 바꾸면 상세 화면을 닫는다
  useEffect(() => setDetail(null), [sub, visible]);

  useEffect(() => {
    fetchHealth().then((h) => { if (h.medium_timeout_sec) setTimeoutSec(h.medium_timeout_sec); }).catch(() => {});
  }, []);

  // 탭이 보일 때만 2초마다 폴더를 스캔한다.
  useEffect(() => {
    if (!visible) return;
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
  }, [visible]);

  if (!visible) return null;

  const showPid = (pid: number) => setDetail({ kind: "pid", pid });
  const showFile = (target: string) => setDetail({ kind: "file", target });
  if (detail?.kind === "pid") {
    return <PidDetail pid={detail.pid} events={events} onBack={() => setDetail(null)}
      onFile={showFile} onAskAi={onAskAi} />;
  }
  if (detail?.kind === "file") {
    return <FileDetail target={detail.target} events={events} onBack={() => setDetail(null)} onPid={showPid} />;
  }

  const label = FILES_SUBS.find(([k]) => k === sub)?.[1];
  return (
    <>
      <p className="crumb">파일 현황 › <b>{label}</b><span>{updated}</span></p>
      {sub === "compare" && <CompareView data={data} events={events} onFile={showFile} />}
      {sub === "honeypot" && <HoneypotView data={data} events={events} onFile={showFile} onPid={showPid} />}
      {sub === "pending" && <PendingView events={events} timeoutSec={timeoutSec} onPid={showPid} />}
    </>
  );
}
