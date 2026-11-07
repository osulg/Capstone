import { useEffect, useLayoutEffect, useRef, useState } from "react";

import type { AiStatus, ChatMessage } from "../hooks/useChat";

interface Props {
  messages: ChatMessage[];
  busy: boolean;
  status: AiStatus;
  onAsk: (text: string) => void;
}

// AI 분석관: 다른 메뉴처럼 본문 전체를 쓰는 화면. 대화 내용은 App의 useChat이 들고 있어서
// 다른 메뉴로 갔다 와도 그대로 남는다.
export default function AiView({ messages, busy, status, onAsk }: Props) {
  const [input, setInput] = useState("");
  const chatRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useLayoutEffect(() => {
    const c = chatRef.current;
    if (c) c.scrollTop = c.scrollHeight;
  }, [messages]);

  useEffect(() => { inputRef.current?.focus(); }, []);

  // 입력 내용에 맞춰 높이 조절 (최대 120px). 첫 화면에서는 CSS 기본 높이를 그대로 둔다.
  const typed = useRef(false);
  useLayoutEffect(() => {
    const t = inputRef.current;
    if (!t || !typed.current) return;
    t.style.height = "auto";
    t.style.height = Math.min(t.scrollHeight, 120) + "px";
  }, [input]);

  const send = () => {
    if (!input.trim()) return;
    onAsk(input);
    setInput("");
  };

  return (
    <fieldset className="ai-view">
      <legend>AI 분석관</legend>
      <div className="ai-bar">
        <span className="caption">수신된 이벤트 로그를 근거로 공격 경위와 대응 방안을 답합니다.</span>
        <span className={`ai-status ${status.className}`} title={status.title}>{status.text.replace("● ", "")}</span>
      </div>

      <div className="ai-chat" ref={chatRef}>
        {messages.length === 0 && (
          <div className="ai-intro">
            예) "pid 905425가 뭘 한건지 알려줘", "최근 HIGH 격상 정리해줘", "대응 방안 알려줘"<br />
            PID 상세 화면의 "AI 분석관에게 이 PID 분석 요청" 버튼으로도 물어볼 수 있습니다.
          </div>
        )}
        {messages.map((m) => (
          <div key={m.id} className={`ai-msg ${m.role}`}>
            <div className="ai-who">{m.role === "ai" ? "AI 분석관" : "나"}</div>
            {m.pending
              ? <div className="ai-box">분석 중…</div>
              /* html은 useChat에서 esc()/markdown()으로 이스케이프한 결과다 */
              : <div className="ai-box" dangerouslySetInnerHTML={{ __html: m.html }} />}
          </div>
        ))}
      </div>

      <div className="ai-composer">
        <textarea ref={inputRef} rows={2} placeholder="질문을 입력하세요"
          value={input} onChange={(e) => { typed.current = true; setInput(e.target.value); }}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) { e.preventDefault(); send(); }
          }} />
        <button className="btn" disabled={busy} onClick={send}>전송</button>
      </div>
    </fieldset>
  );
}
