import { useCallback, useEffect, useRef, useState } from "react";

import AiView from "./components/AiView";
import EventsView from "./components/EventsView";
import FilesView from "./components/FilesView";
import Header from "./components/Header";
import StatusBar from "./components/StatusBar";
import SystemView from "./components/SystemView";
import Tabs, { type FilesSub, type View } from "./components/Tabs";
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

  // PID 상세의 "AI 분석관에게 이 PID 분석 요청" 버튼
  const askAiPid = (pid: number) => {
    setView("ai");
    chat.ask(`pid ${pid}가 뭘 한건지 알려줘. 왜 격상됐는지도 설명해줘.`);
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
