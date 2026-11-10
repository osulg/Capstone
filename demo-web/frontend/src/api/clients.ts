import type { ScenarioRunMode, Run, RunCreated, Scenario, } from "../types/api";

/** 서버가 HTTP 오류 응답을 반환한 경우 */
export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

function errorMessage(body: unknown, status: number): string {
  if (typeof body === "object" && body !== null && "detail" in body) {
    if (typeof body.detail === "string") return body.detail;
    if (Array.isArray(body.detail)) return "요청 값이 올바르지 않습니다.";
  }

  return `요청 실패 (${status})`;
}

async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  // 연결 오류는 fetch가 발생시킨 오류를 그대로 전달한다.
  const response = await fetch(path, options);
  const text = await response.text();

  let body: unknown;

  try {
    body = JSON.parse(text) as unknown;
  } catch {
    if (!response.ok) {
      throw new ApiError(
        response.status,
        `요청 실패 (${response.status})`,
      );
    }

    throw new Error("서버에서 올바른 JSON 응답을 받지 못했습니다.");
  }

  if (!response.ok) {
    throw new ApiError(
      response.status,
      errorMessage(body, response.status),
    );
  }

  return body as T;
}

export function getScenarios(): Promise<Scenario[]> {
  return request<Scenario[]>("/api/scenarios");
}

export function startRun(
  scenarioId: string,
  mode: ScenarioRunMode | null = null,
): Promise<RunCreated> {
  const payload =
    scenarioId === "S02" || scenarioId === "S03"
      ? { scenario_id: scenarioId, mode }
      : { scenario_id: scenarioId };

  return request<RunCreated>("/api/runs", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
}

export function getRun(runId: string): Promise<Run> {
  return request<Run>(
    `/api/runs/${encodeURIComponent(runId)}`,
  );
}

/** 테스트 프로세스 종료를 요청한다. HoldFS 대기 작업의 취소 요청은 아니다. */
export function cancelRun(runId: string): Promise<Run> {
  return request<Run>(
    `/api/runs/${encodeURIComponent(runId)}/cancel`,
    { method: "POST" },
  );
}
