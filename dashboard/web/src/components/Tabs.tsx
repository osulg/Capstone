export type View = "events" | "files" | "system" | "ai";
export type FilesSub = "runs" | "honeypot";

export const FILES_SUBS: [FilesSub, string][] = [
  ["runs", "실행별 상세"],
  ["honeypot", "미끼 파일 상태"],
];

interface Props {
  view: View;
  onView: (v: View) => void;
  filesSub: FilesSub;
  onFilesSub: (s: FilesSub) => void;
  aiDot: boolean;          // AI 분석관 화면이 아닐 때 새 답변이 왔는지
}

export default function Tabs({ view, onView, filesSub, onFilesSub, aiDot }: Props) {
  const filesOpen = view === "files";
  return (
    <nav className="tabs" role="tablist" aria-label="대시보드 메뉴">
      <button className="tab" role="tab" aria-selected={view === "events"} onClick={() => onView("events")}>
        보안 이벤트 현황
      </button>

      {/* 파일 현황: 왼쪽 메뉴에서는 하위 메뉴를 항상 펼쳐 둔다.
          좁은 화면(위쪽 가로 메뉴)에서는 파일 현황을 볼 때만 보인다 (styles.css의 .tree.open) */}
      <div className={`tree${filesOpen ? " open" : ""}`}>
        <button className="tab" role="tab" aria-selected={filesOpen} onClick={() => onView("files")}>
          파일 현황
        </button>
        <ul className="tree-sub">
          {FILES_SUBS.map(([key, label]) => (
            <li key={key}>
              <button className="sub" aria-current={filesOpen && filesSub === key}
                onClick={() => { onFilesSub(key); onView("files"); }}>
                {label}
              </button>
            </li>
          ))}
        </ul>
      </div>

      <button className="tab" role="tab" aria-selected={view === "system"} onClick={() => onView("system")}>
        시스템 현황
      </button>

      <button className="tab ai-tab" role="tab" aria-selected={view === "ai"} onClick={() => onView("ai")}>
        AI 분석관{aiDot && view !== "ai" && <span className="ai-dot" title="새 답변">●</span>}
      </button>
    </nav>
  );
}
