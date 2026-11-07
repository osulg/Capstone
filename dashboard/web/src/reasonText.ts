// HoldFS 로그(동작 · 결과 · 사유)를 화면에 보여줄 말로 바꾼다.
// PID 상세의 전체 로그, 파일 상세의 파일 이력, 그래프 말풍선이 같이 쓴다.
// 원문은 각 행에 마우스를 올리면 보이도록 rawText()로 남긴다.
import { useEffect, useState } from "react";

import { fetchHealth } from "./api";
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

// Stage 1 이 의심 대상으로 올린 이유
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
const osError = (r: string) => (r || "").split(";")[0].trim() || "-";

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
  if (code.startsWith("high_entropy_write")) return "고엔트로피 쓰기";
  if (code.startsWith("magic_mismatch")) return "파일 형식 시그니처 불일치";
  if (code.startsWith("global_buffer_limit_exceeded")) return "전체 보류 한도 초과";
  if (code.startsWith("buffer_limit_exceeded")) return "파일 보류 한도 초과";
  if (code.startsWith("structural_check_failed")) return "반영 전 파일 구조 문제 발견";
  if (code === "forced_state") return "테스트용 강제 상태";
  if (code === "High-risk process detected") return "고위험 프로세스";
  return code;
}

// HIGH 격상 이벤트(agent 가 만든 'HIGH사유, stage1=…, dyn=…' 문장)에서 HIGH 사유만 꺼내 풀어 쓴다
export const highEscalateText = (reason: string, th: Thresholds) =>
  highReasonText((reason || "").split(", ")[0], th);

// HIGH 를 일으킨 쓰기·반영 기록 (medium.py 의 ESCALATED_TO_HIGH / VALIDATION_FAILED)
export const isHighCause = (e: EdrEvent) =>
  e.result === "ESCALATED_TO_HIGH" || (e.action === "COMMIT" && e.result === "VALIDATION_FAILED");

// 격상 원인 기록의 원인만 (파일 경로는 대상 파일 칸에 있으므로 붙이지 않는다)
export function causeText(e: EdrEvent): string {
  const r = e.reason || "";
  if (e.result === "VALIDATION_FAILED" || r.startsWith("structural_check")) return "반영 전 파일 구조 문제 발견";
  if (r.startsWith("magic number")) return "파일 형식 시그니처 불일치";
  if (r.startsWith("high_entropy")) return "고엔트로피 쓰기";
  if (r.startsWith("global_buffer_limit_exceeded")) return "전체 보류 한도 초과";
  if (r.startsWith("buffer_limit_exceeded")) return "파일 보류 한도 초과";
  return r;
}

// 숨기는 기록 판단은 eventStats 에 있다 (파일별 목록도 같이 쓰기 때문)
export { isHiddenEvent } from "./eventStats";

// SETATTR 사유(CHMOD(...),CHOWN(uid),UTIME(mtime) …)에서 바뀐 종류를 뽑는다
function attrKinds(reason: string): string[] {
  const kinds: string[] = [];
  if (/CHMOD/.test(reason)) kinds.push("권한");
  if (/CHOWN/.test(reason)) kinds.push("소유자");
  if (/UTIME/.test(reason)) kinds.push("시간");
  return kinds;
}

// HIGH 상태에서 차단된 동작 이름
function blockedName(action: string): string {
  if (action === "WRITE") return "쓰기 차단";
  if (action === "DELETE") return "삭제 차단";
  if (action === "RENAME") return "이름 변경 차단";
  if (action.startsWith("TRUNCATE") || action === "OPEN(O_TRUNC)") return "자르기 차단";
  if (action === "CREATE") return "생성 차단";
  if (action === "MKDIR") return "폴더 생성 차단";
  if (action === "RMDIR") return "폴더 삭제 차단";
  if (/^(CHMOD|CHOWN|UTIME)/.test(action)) return "권한 변경 차단";
  return `${action} 차단`;
}

export interface Described { action: string; detail: string }

// 원문 (마우스를 올렸을 때 보여줄 말풍선)
export const rawText = (e: EdrEvent) => [e.action, e.result, e.reason].filter(Boolean).join(" · ");

// 기록 하나 → 동작 / 상세. setattrFrom 은 SETATTR · CONFIRMED 가 무엇을 반영했는지 찾을 때 쓰는 직전 보류 기록.
export function describeEvent(e: EdrEvent, th: Thresholds, setattrFrom?: EdrEvent): Described {
  const r = e.reason || "";
  const isDir = e.action === "RMDIR";

  if (e.result === "BLOCKED" && /honeypot/i.test(r)) return { action: "허니팟 접근 차단", detail: "미끼 파일 접근 차단" };

  switch (e.action) {
    case "ESCALATE":
      if (e.level === "HIGH") return { action: "HIGH 격상", detail: highEscalateText(r, th) };
      if (r.startsWith("untrusted_origin")) return { action: `${e.level} 격상`, detail: "비신뢰 경로 실행" };
      {
        const sc = r.match(/(?:최초 평가|재채점) score=([\d.]+)/);
        return { action: `${e.level} 격상`, detail: sc ? `ML 점수 ${score(sc[1])}` : r };
      }
    case "RETURN": return { action: "정상 복귀", detail: "재평가 결과 정상" };
    case "SIGSTOP": return { action: "프로세스 정지", detail: "프로세스 일시정지" };
    case "DETECT": {
      const det = r.split(":")[0].trim();
      return { action: "Stage 1 탐지", detail: STAGE1[det] ?? r };
    }
  }

  switch (e.result) {
    case "ESCALATED_TO_HIGH": return { action: "위험 쓰기 감지", detail: `${causeText(e)}, HIGH 격상` };
    case "VALIDATION_FAILED": return { action: "반영 전 파일 구조 문제 발견", detail: "반영 거부, HIGH 격상" };
    case "BUFFERED":
      if (e.action === "SETATTR") {
        const k = attrKinds(r);
        return { action: "권한 변경 보류", detail: k.length ? k.map((x) => `${x} 변경 보류`).join(", ") : "권한 변경 보류" };
      }
      return { action: "쓰기 보류", detail: "판정 전까지 원본에 반영 안 함" };
    case "ALLOWED": return { action: "폴더 생성", detail: "지연 뒤 허용" };
    case "STAGED": return { action: isDir ? "폴더 삭제 보관" : "파일 삭제 보관", detail: "판정 전까지 보류" };
    case "CONFIRMED":
      if (e.action === "SETATTR") {
        const k = setattrFrom ? attrKinds(setattrFrom.reason || "") : [];
        return { action: "권한 변경 반영", detail: k.length ? k.map((x) => `${x} 변경 반영`).join(", ") : "권한 변경 반영" };
      }
      return { action: isDir ? "폴더 삭제 허용" : "삭제 허용", detail: "LOW 판정으로 인한 삭제 허용" };
    case "RESTORED": return { action: isDir ? "폴더 삭제 거부" : "삭제 거부", detail: "HIGH 판정으로 인한 삭제 거부, 원본 보존" };
    case "FILE_APPLIED": return { action: "파일 쓰기 반영", detail: "판정 완료, 파일 쓰기 반영" };
    case "DATA_APPLIED": return { action: "파일 쓰기 반영 완료", detail: "프로세스의 모든 쓰기 반영 완료" };
    case "BUFFER_DROPPED": {
      const n = Number(r.match(/버퍼 (\d+)개/)?.[1] ?? 1);
      return { action: "보류 쓰기 폐기", detail: n > 0 ? `보류 쓰기 ${n}건 폐기, 원본 보존` : "버릴 쓰기 없음" };
    }
    case "RESTORE_CONFLICT":
    case "STAGING_PRESERVED":
      return { action: "임시 폴더 보존", detail: "파일 반영 및 복구 문제 발생, 임시 폴더 확인 필요" };
    case "APPLY_FAILED":
    case "IO_FAILED":
    case "NOT_COMPLETED":
      return { action: "반영 실패", detail: osError(r) };
    case "RESTORE_FAILED":
    case "RESTORE_CLEANUP_FAILED":
      return { action: "복원 실패", detail: osError(r) };
    case "FINALIZE_FAILED": return { action: "삭제 확정 실패", detail: osError(r) };
    case "CLEANUP_FAILED":
    case "HANDLE_CLEANUP_FAILED":
      return { action: "정리 실패", detail: osError(r) };
    case "BLOCKED":
      if (e.level === "HIGH") return { action: blockedName(e.action), detail: "HIGH 판정, 차단" };
  }
  return { action: `${e.action} ${e.result}`.trim(), detail: r };
}

// SETATTR · CONFIRMED 마다 같은 파일의 직전 SETATTR · BUFFERED 기록을 찾아 둔다
export function setattrSources(rows: EdrEvent[]): Map<number, EdrEvent> {
  const out = new Map<number, EdrEvent>();
  const lastBuf = new Map<string, EdrEvent>();
  for (const e of rows) {
    if (e.action !== "SETATTR") continue;
    if (e.result === "BUFFERED") lastBuf.set(e.target, e);
    else if (e.result === "CONFIRMED" && lastBuf.has(e.target)) out.set(e.id, lastBuf.get(e.target)!);
  }
  return out;
}
