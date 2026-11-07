// HoldFS 로그의 사유 코드를 화면에 보여줄 말로 바꾼다 (진행 흐름, 그래프 말풍선).
// 원본 문장은 PID 상세의 '전체 로그' 표에 그대로 남긴다.
import { useEffect, useState } from "react";

import { fetchHealth } from "./api";
import { shortPath } from "./eventStats";
import type { EdrEvent } from "./types";

// Stage 2 판정 기준 (config.STAGE2_*). 서버 /api/health 가 config.py 값을 넘겨준다.
export interface Thresholds { high?: number; dynOnly?: number }

let cached: Thresholds | null = null;
export function useThresholds(): Thresholds {
  const [t, setT] = useState<Thresholds>(cached ?? {});
  useEffect(() => {
    if (cached) return;
    fetchHealth()
      .then((h) => { cached = { high: h.high_threshold, dynOnly: h.dyn_only_threshold }; setT(cached); })
      .catch(() => {});
  }, []);
  return t;
}

// 확장자 그룹 (config.EXTENSION_GROUPS)
const EXT_GROUP: Record<string, string> = {
  HIGH_VALUE: "문서·이미지", COMPRESSED: "압축", PLAIN_TEXT: "텍스트", UNKNOWN: "기타",
};
const group = (g: string) => EXT_GROUP[g] ?? g;

// Stage 1이 의심 대상으로 올린 이유
const STAGE1: Record<string, string> = {
  HoneypotDetector: "허니팟 접근",
  ExtChangeDetector: "확장자 변경 반복",
  EntropyBurstDetector: "고엔트로피 쓰기 집중",
  EntropyDetector: "고엔트로피 쓰기",
  EntropyDeltaDetector: "파일 엔트로피 급변",
  stat_anomaly: "파일 작업 급증",
  stage1_sampling: "비신뢰 경로 신규 프로세스",
};

const score = (v: string) => Number(v).toFixed(3);
const basis = (t?: number) => (t === undefined ? "" : ` (기준 ${t})`);

// HIGH 로 올라간 이유 코드 (stage2_worker.py / medium.py 의 trigger_high reason)
export function highReasonText(code: string, th: Thresholds): string {
  let m: RegExpMatchArray | null;
  if ((m = code.match(/^(ml_score|watch_score|reeval_score)=([\d.]+)/))) {
    const when = m[1] === "ml_score" ? "ML 점수" : m[1] === "watch_score" ? "관찰 중 ML 점수" : "재평가 ML 점수";
    return `${when} ${score(m[2])}${basis(th.high)}`;
  }
  if ((m = code.match(/^(dyn_only|watch_dyn_only|reeval_dyn_only)=([\d.]+)/))) {
    return `동적 점수 ${score(m[2])} 단독 초과${basis(th.dynOnly)}`;
  }
  if ((m = code.match(/^high_entropy_write\(ext=(\w+)\)/))) return `${group(m[1])} 파일에 고엔트로피 쓰기`;
  if (code.startsWith("magic_mismatch")) return "파일 형식 시그니처 불일치";
  if (code.startsWith("global_buffer_limit_exceeded")) return "전체 보류 한도 초과";
  if (code.startsWith("buffer_limit_exceeded")) return "파일 보류 한도 초과";
  if (code.startsWith("structural_check_failed")) return "반영 전 파일 구조 검사 실패";
  if (code === "forced_state") return "테스트용 강제 상태";
  if (code === "High-risk process detected") return "고위험 프로세스";
  return code;
}

// HIGH 를 일으킨 쓰기·반영 기록 (medium.py 의 ESCALATED_TO_HIGH / VALIDATION_FAILED)
export const isHighCause = (e: EdrEvent) =>
  e.result === "ESCALATED_TO_HIGH" || (e.action === "COMMIT" && e.result === "VALIDATION_FAILED");

export function causeText(e: EdrEvent): string {
  const r = e.reason || "";
  let m: RegExpMatchArray | null;
  let what = r;
  if (r.startsWith("magic number")) what = "파일 형식 시그니처 불일치";
  else if ((m = r.match(/^high_entropy\(ext=(\w+)/))) what = `${group(m[1])} 파일에 고엔트로피 쓰기`;
  else if (r.startsWith("global_buffer_limit_exceeded")) what = "전체 보류 한도 초과";
  else if (r.startsWith("buffer_limit_exceeded")) what = "파일 보류 한도 초과";
  else if (r.startsWith("structural_check")) what = "반영 전 파일 구조 검사 실패";
  return e.target ? `${what} · ${shortPath(e.target)}` : what;
}

// HIGH 격상 이벤트(agent 가 만든 'HIGH사유, stage1=…, dyn=…' 문장)에서 HIGH 사유만 꺼내 풀어 쓴다
export function highEscalateText(reason: string, th: Thresholds): string {
  const code = (reason || "").split(", ")[0];
  return highReasonText(code, th);
}

// MEDIUM 격상 이벤트의 사유
export function mediumEscalateText(reason: string): string {
  const r = reason || "";
  if (r.startsWith("untrusted_origin")) return "비신뢰 경로에서 실행 → 먼저 감시";
  const parts: string[] = [];
  const s1 = r.match(/stage1=(\w+)/);
  if (s1) parts.push(`의심 원인: ${STAGE1[s1[1]] ?? s1[1]}`);
  const sc = r.match(/(?:최초 평가|재채점) score=([\d.]+)/);
  if (sc) parts.push(`ML 점수 ${score(sc[1])}`);
  return parts.length ? parts.join(" · ") : r;
}
