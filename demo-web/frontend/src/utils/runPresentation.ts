import type { Run, RunStatus } from "../types/api";

const STATUS_LABELS: Record<RunStatus, string> = {
  queued: "실행 대기",
  running: "실행 중",
  cancelling: "프로세스 종료 중",
  passed: "작업 관찰 완료",
  failed: "실행 실패",
  timed_out: "시간 초과",
  cancelled: "테스트 프로세스 종료됨",
};

export function hasConfirmedPolicyBlock(run: Run): boolean {
  const block = run.result?.policy_block;

  return (
    (run.scenario_id === "S01" || run.scenario_id === "S03") &&
    block !== null &&
    typeof block === "object" &&
    "confirmed" in block &&
    block.confirmed === true &&
    "process_reaped" in block &&
    block.process_reaped === true
  );
}

export function getRunPresentation(run: Run): {
  label: string;
  tone: "success" | "error" | "neutral";
} {
  // 진행 중과 사용자 중단 상태를 최종 보호 결과로 덮어쓰지 않는다.
  if (
    run.status === "queued" ||
    run.status === "running" ||
    run.status === "cancelling" ||
    run.status === "cancelled"
  ) {
    return {
      label: STATUS_LABELS[run.status],
      tone: "neutral",
    };
  }

  const protection = run.protection_verification?.status;
  const honeypot =
    run.scenario_id === "S02" && run.mode === "honeypot";

  if (protection === "passed") {
    return {
      label: honeypot ? "접근 차단 확인" : "보호 검증 완료",
      tone: "success",
    };
  }

  if (protection === "failed") {
    return {
      label: "보호 검증 실패",
      tone: "error",
    };
  }

  if (hasConfirmedPolicyBlock(run)) {
    return {
      label: "정책 차단 종료 · 보호 판정 미확정",
      tone: "neutral",
    };
  }

  if (honeypot) {
    return {
      label: protection === "unknown"
        ? "보호 판정 불가"
        : "접근 관찰 완료",
      tone: run.status === "passed" ? "neutral" : "error",
    };
  }

  return {
    label: STATUS_LABELS[run.status],
    tone: run.status === "passed" ? "success" : "error",
  };
}
