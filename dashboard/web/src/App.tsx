import { useCallback, useEffect, useRef, useState } from "react";

import AiView from "./components/AiView";
import EventsView from "./components/EventsView";
import FilesView from "./components/FilesView";
import Header from "./components/Header";
import StatusBar from "./components/StatusBar";
import SystemView from "./components/SystemView";
import Tabs, { type FilesSub, type View } from "./components/Tabs";
import { byPid } from "./eventStats";
import { useChat } from "./hooks/useChat";
import { useEvents } from "./hooks/useEvents";

export default function App() {
  const { events, online, lastUpdate } = useEvents();
  const [view, setView] = useState<View>("events");
  const [filesSub, setFilesSub] = useState<FilesSub>("compare");

  // AI 분석관: 대화는 여기서 들고 있어서 메뉴를 옮겨도 남는다.
  // 다른 화면을 보는 동안 답변이 오면 메뉴에 ● 표시를 켠다.
  const [aiDot, setAiDot] = useState(false);
  const viewRef = useRef(view);
  useEffect(() => { viewRef.current = view; if (view === "ai") setAiDot(false); }, [view]);
  const onReply = useCallback(() => { if (viewRef.current !== "ai") setAiDot(true); }, []);
  const chat = useChat(onReply);

  // PID 상세의 "AI 분석관에게 이 PID 분석 요청" 버튼.
  // 그 PID 가 실제로 도달한 최고 상태에 맞춰 질문을 바꾼다 (격상되지 않은 PID 에 '왜 격상됐는지'를 묻지 않도록).
  const askAiPid = (pid: number) => {
    setView("ai");
    const level = byPid(events).find((r) => r.pid === pid)?.level ?? "LOW";
    chat.ask(aiPidQuestion(pid, level));
  };

  return (
    <div className="window">
      <Header />
      <Tabs view={view} onView={setView} filesSub={filesSub} onFilesSub={setFilesSub}
        aiDot={aiDot} />
      <div className="main-layout">
        <section className="panel">
          {view === "events" && <EventsView events={events} onAskAi={askAiPid} />}
          <FilesView visible={view === "files"} sub={filesSub} events={events} onAskAi={askAiPid} />
          {view === "system" && <SystemView events={events} onAskAi={askAiPid} />}
          {view === "ai" && <AiView messages={chat.messages} busy={chat.busy} status={chat.status} onAsk={chat.ask} />}
        </section>
      </div>
      <StatusBar online={online} lastUpdate={lastUpdate} events={events} />
    </div>
  );
}

function aiPidQuestion(pid: number, level: string): string {
  const head = `pid ${pid}가 뭘 한건지 알려줘.`;
  switch (level) {
    case "HIGH": return `${head} 왜 HIGH로 격상됐는지도 설명해줘.`;
    case "MEDIUM": return `${head} 왜 MEDIUM으로 감시됐는지, 그 뒤 어떻게 판정됐는지도 설명해줘.`;
    case "SUSPICIOUS": return `${head} 어떤 탐지에 걸렸는지, 그리고 왜 MEDIUM/HIGH로 격상되지 않았는지도 설명해줘.`;
    default: return `${head} 격상 없이 정상(LOW)으로 처리된 이유도 설명해줘.`;
  }
}
