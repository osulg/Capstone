import { useCallback, useState } from "react";

// 목록의 '화면 정리' 시각(ms). 이 시각 이전 기록은 화면에서만 숨긴다 (서버 기록·로그 파일은 그대로).
// 새로고침해도 유지되도록 이 브라우저에만 저장한다. 저장소를 쓸 수 없으면 이번 화면에서만 적용한다.
const read = (key: string): number | null => {
  try {
    const v = window.localStorage.getItem(key);
    const n = v === null ? NaN : Number(v);
    return Number.isFinite(n) ? n : null;
  } catch {
    return null;
  }
};

const write = (key: string, value: number | null) => {
  try {
    if (value === null) window.localStorage.removeItem(key);
    else window.localStorage.setItem(key, String(value));
  } catch {
    /* 저장소를 쓸 수 없는 환경: 화면 상태만 바꾼다 */
  }
};

export function useClearMark(key: string) {
  const [mark, setMark] = useState<number | null>(() => read(key));
  const clear = useCallback(() => { const now = Date.now(); write(key, now); setMark(now); }, [key]);
  const reset = useCallback(() => { write(key, null); setMark(null); }, [key]);
  return { mark, clear, reset };
}
