interface Props {
  online: boolean;
  lastUpdate: string;
}

export default function Header({ online, lastUpdate }: Props) {
  return (
    <header>
      <div className="logo">
        <div className="logo-icon">CC</div>
        <h1>HoldFS EDR<span>Endpoint Detection &amp; Response</span></h1>
      </div>
      <div className="header-right">
        <div className={`live-dot${online ? "" : " offline"}`} id="live">
          {online ? "실시간 모니터링" : "서버 연결 끊김"}
        </div>
        <div id="last-update">{lastUpdate}</div>
      </div>
    </header>
  );
}
