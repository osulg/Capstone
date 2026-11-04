export type View = "events" | "files";

interface Props {
  view: View;
  onView: (v: View) => void;
  aiOpen: boolean;
  aiDot: boolean;
  onToggleAi: () => void;
}

export default function SideRail({ view, onView, aiOpen, aiDot, onToggleAi }: Props) {
  return (
    <nav className="side-rail" aria-label="화면 전환">
      <button className={`rail-tab${view === "events" ? " active" : ""}`} id="tab-events"
        title="보안 이벤트 로그" onClick={() => onView("events")}>
        <span className="rail-icon">📋</span>이벤트
      </button>
      <button className={`rail-tab${view === "files" ? " active" : ""}`} id="tab-files"
        title="파일 상태 (보호 vs 비보호 비교)" onClick={() => onView("files")}>
        <span className="rail-icon">📁</span>파일 상태
      </button>
      <button className={`rail-tab ai${aiOpen ? " active" : ""}`} id="tab-ai"
        title="AI 보안 분석관 열기/닫기" aria-expanded={aiOpen} aria-controls="ai-pane" onClick={onToggleAi}>
        <span className="rail-icon">🤖</span>AI 분석관
        <span className={`rail-dot${aiDot ? " show" : ""}`} id="ai-dot"></span>
      </button>
    </nav>
  );
}
