import { useCallback, useEffect, useRef, useState } from "react";

import AiPane from "./components/AiPane";
import EventsView from "./components/EventsView";
import FilesView from "./components/FilesView";
import Header from "./components/Header";
import SideRail, { type View } from "./components/SideRail";
import { useChat } from "./hooks/useChat";
import { useEvents } from "./hooks/useEvents";

export default function App() {
  const { events, stats, newIds, setNewIds, online, lastUpdate } = useEvents();
  const [view, setView] = useState<View>("events");
  // AI 분석관 패널 (기본: 닫힘 → 이벤트 로그 전체 화면)
  const [aiOpen, setAiOpenState] = useState(false);
  const [aiDot, setAiDot] = useState(false);
  const aiOpenRef = useRef(false);

  const setAiOpen = useCallback((open: boolean) => {
    aiOpenRef.current = open;
    setAiOpenState(open);
    if (open) setAiDot(false);
  }, []);

  // 패널이 닫혀 있을 때 답변이 오면 탭에 알림 점을 켠다.
  const onReply = useCallback(() => { if (!aiOpenRef.current) setAiDot(true); }, []);
  const chat = useChat(onReply);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape" && aiOpenRef.current) setAiOpen(false); };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [setAiOpen]);

  const askPid = (pid: number) => {
    setAiOpen(true);
    chat.ask(`pid ${pid}가 뭘 한건지 알려줘. 왜 격상됐는지도 설명해줘.`);
  };

  return (
    <>
      <Header online={online} lastUpdate={lastUpdate} />
      <div className={`main-layout${aiOpen ? " ai-open" : ""}`} id="layout">
        <SideRail view={view} onView={setView} aiOpen={aiOpen} aiDot={aiDot} onToggleAi={() => setAiOpen(!aiOpen)} />
        <main className="dashboard-pane">
          <EventsView hidden={view !== "events"} events={events} stats={stats} newIds={newIds}
            onFilterChange={() => setNewIds(new Set())} onPidClick={askPid} />
          <FilesView visible={view === "files"} />
        </main>
        <AiPane open={aiOpen} messages={chat.messages} busy={chat.busy} status={chat.status}
          onAsk={chat.ask} onClose={() => setAiOpen(false)} />
      </div>
    </>
  );
}
