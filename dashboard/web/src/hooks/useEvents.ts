import { useEffect, useRef, useState } from "react";

import { fetchEvents } from "../api";
import type { EdrEvent, EventStats } from "../types";

const POLL_MS = 2000;

const EMPTY_STATS: EventStats = { total: 0, high: 0, medium: 0, blocked: 0 };

// /api/events 증분 폴링. 서버가 이벤트를 지우면(gen 변경) reset으로 전체를 다시 받는다.
export function useEvents() {
  const [events, setEvents] = useState<EdrEvent[]>([]);
  const [stats, setStats] = useState<EventStats>(EMPTY_STATS);
  const [newIds, setNewIds] = useState<Set<number>>(new Set());
  const [online, setOnline] = useState(true);
  const [lastUpdate, setLastUpdate] = useState("-");
  const cursor = useRef({ lastId: 0, gen: 0 });

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const data = await fetchEvents(cursor.current.lastId, cursor.current.gen);
        if (!alive) return;
        cursor.current = { lastId: data.last_id, gen: data.gen };
        if (data.reset) {
          setEvents(data.events);
          setNewIds(new Set());
        } else if (data.events.length) {
          setEvents((prev) => [...prev, ...data.events]);
          setNewIds(new Set(data.events.map((e) => e.id)));
        }
        setStats(data.stats);
        setOnline(true);
        setLastUpdate(
          new Date().toLocaleTimeString("ko-KR", { hour: "numeric", minute: "2-digit", second: "2-digit" }) + " 갱신",
        );
      } catch {
        if (alive) setOnline(false);
      }
    };
    tick();
    const timer = setInterval(tick, POLL_MS);
    return () => { alive = false; clearInterval(timer); };
  }, []);

  return { events, stats, newIds, setNewIds, online, lastUpdate };
}
