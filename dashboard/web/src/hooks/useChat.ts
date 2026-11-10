import { useCallback, useEffect, useRef, useState } from "react";

import { fetchHealth, postChat } from "../api";
import { esc, markdown } from "../markdown";
import type { ChatTurn } from "../types";

export interface ChatMessage {
  id: number;
  role: "user" | "ai";
  html: string;      // 이미 이스케이프된 HTML
  pending?: boolean;
}

export interface AiStatus {
  className: string;
  text: string;
  title?: string;
}

const READY: AiStatus = { className: "", text: "● 준비됨" };

// AI 분석관 대화 상태. onReply는 패널이 닫혀 있을 때 알림 점을 켜는 데 쓴다.
export function useChat(onReply: () => void) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<AiStatus>(READY);
  const history = useRef<ChatTurn[]>([]);
  const busyRef = useRef(false);
  const nextId = useRef(1);

  const refreshHealth = useCallback(async () => {
    try {
      const h = await fetchHealth();
      setStatus(h.llm
        ? { className: "", text: "● 준비됨", title: h.model }
        : { className: "local", text: "● 로컬 모드", title: "OPENAI_API_KEY 미설정 — 규칙 기반 분석" });
    } catch {
      /* 폴링에서 연결 상태 표시 */
    }
  }, []);

  useEffect(() => { refreshHealth(); }, [refreshHealth]);

  const ask = useCallback(async (raw: string) => {
    const text = (raw || "").trim();
    if (!text || busyRef.current) return;
    busyRef.current = true;
    setBusy(true);
    setStatus({ className: "busy", text: "● 분석 중" });

    const userId = nextId.current++;
    const aiId = nextId.current++;
    setMessages((m) => [...m, { id: userId, role: "user", html: esc(text) },
      { id: aiId, role: "ai", html: "", pending: true }]);
    const settle = (html: string) =>
      setMessages((m) => m.map((x) => (x.id === aiId ? { ...x, html, pending: false } : x)));

    try {
      const data = await postChat(text, history.current);
      // 근거로 함께 보낸 PID·문서 목록(sources)은 답변과 무관해 보일 수 있어 화면에 표시하지 않는다.
      settle(markdown(data.reply));
      onReply();
      history.current = [...history.current, { role: "user" as const, content: text },
        { role: "assistant" as const, content: data.reply }].slice(-16);
    } catch (e) {
      settle(`<blockquote>분석 요청 실패: ${esc((e as Error).message)}</blockquote>`);
    } finally {
      busyRef.current = false;
      setBusy(false);
      refreshHealth();
    }
  }, [onReply, refreshHealth]);

  return { messages, busy, status, ask };
}
