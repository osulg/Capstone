import type { EdrEvent } from "../types";

interface Props {
  online: boolean;
  lastUpdate: string;
  events: EdrEvent[];
}

export default function StatusBar({ online, lastUpdate, events }: Props) {
  // 받은 순서가 아니라 이벤트 시각 기준으로 가장 최근 것
  const last = events.reduce<EdrEvent | undefined>((m, e) => (!m || e.time > m.time ? e : m), undefined);
  return (
    <div className="statusbar">
      <span>서버: {online ? "연결됨" : "연결 끊김"}</span>
      <span>마지막 이벤트: {last ? last.time.slice(11) : "-"}</span>
      <span>이벤트 {events.length}건</span>
      <span>{lastUpdate === "-" ? "갱신 대기" : `마지막 ${lastUpdate}`}</span>
    </div>
  );
}
