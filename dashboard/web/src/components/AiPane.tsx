import { useEffect, useLayoutEffect, useRef, useState } from "react";

import type { AiStatus, ChatMessage } from "../hooks/useChat";

interface Props {
  open: boolean;
  messages: ChatMessage[];
  busy: boolean;
  status: AiStatus;
  onAsk: (text: string) => void;
  onClose: () => void;
}

export default function AiPane({ open, messages, busy, status, onAsk, onClose }: Props) {
  const [input, setInput] = useState("");
  const paneRef = useRef<HTMLElement>(null);
  const chatRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  const scrollToBottom = () => {
    const c = chatRef.current;
    if (c) c.scrollTop = c.scrollHeight;
  };

  useLayoutEffect(scrollToBottom, [messages]);

  // 열릴 때: 좁은 화면이면 패널로 스크롤, 아니면 입력창에 포커스
  useEffect(() => {
    if (!open) return;
    scrollToBottom();
    if (window.matchMedia("(max-width: 960px)").matches) paneRef.current?.scrollIntoView({ behavior: "smooth" });
    else inputRef.current?.focus();
  }, [open]);

  // 입력 내용에 맞춰 높이 조절 (최대 120px). 첫 화면에서는 CSS 기본 높이를 그대로 둔다.
  const typed = useRef(false);
  useLayoutEffect(() => {
    const t = inputRef.current;
    if (!t || !typed.current) return;
    t.style.height = "auto";
    t.style.height = Math.min(t.scrollHeight, 120) + "px";
  }, [input]);

  const send = () => { onAsk(input); setInput(""); };

  return (
    <aside className="ai-pane" id="ai-pane" ref={paneRef}>
      <div className="ai-head">
        <div className="ai-title">
          <div className="ai-icon">🤖</div>
          <div><h3>AI 보안 분석관</h3><small>RAG + LLM 침입 분석</small></div>
        </div>
        <div className="ai-head-right">
          <div id="ai-status" className={status.className} title={status.title}>{status.text}</div>
          <button className="ai-close" id="ai-close" title="닫기" aria-label="AI 분석관 닫기" onClick={onClose}>✕</button>
        </div>
      </div>
      <div className="chat" id="chat" ref={chatRef}>
        <div className="intro">
          <b>⚡ HoldFS AI 보안 분석관</b>
          현재 수신된 EDR 이벤트를 기반으로 침입 시나리오를 분석합니다.<br />
          위협 분석, MITRE ATT&amp;CK 매핑, 대응 방안을 물어보세요.
          표의 PID를 클릭하면 해당 프로세스를 바로 분석합니다.<br />
          패널은 ✕ 버튼, 왼쪽 탭, Esc 키로 닫을 수 있습니다.
        </div>
        {messages.map((m) => (
          <div key={m.id} className={`msg ${m.role}`}>
            <div className="avatar">{m.role === "ai" ? "AI" : "나"}</div>
            {m.pending
              ? <div className="bubble"><div className="typing"><span></span><span></span><span></span></div></div>
              /* html은 useChat에서 esc()/markdown()으로 이스케이프한 결과다 */
              : <div className="bubble" dangerouslySetInnerHTML={{ __html: m.html }} />}
          </div>
        ))}
      </div>
      <div className="composer">
        <textarea id="input" ref={inputRef} rows={1} placeholder="예: pid 905425가 뭘 한건지 알려줘"
          value={input} onChange={(e) => { typed.current = true; setInput(e.target.value); }}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) { e.preventDefault(); send(); }
          }} />
        <button id="send" disabled={busy} onClick={send}>전송</button>
      </div>
    </aside>
  );
}
