import type { Run, RunCreated, Scenario } from "../types/api";

function errorMessage(body: unknown, status: number): string {
  if (typeof body === "object" && body !== null && "detail" in body) {
    if (typeof body.detail === "string") return body.detail;
    if (Array.isArray(body.detail)) return "요청 값이 올바르지 않습니다.";
  }
  return `요청 실패 (${status})`;
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(path, options);
  const text = await response.text();
  let body: unknown;

  try {
    body = JSON.parse(text) as unknown;
  } catch {
    if (!response.ok) throw new Error(`요청 실패 (${response.status})`);
    throw new Error("서버에서 올바른 JSON 응답을 받지 못했습니다.");
  }

  if (!response.ok) {
    throw new Error(errorMessage(body, response.status));
  }

  // Static types describe the API contract; this is not runtime validation.
  return body as T;
}

export function getScenarios(): Promise<Scenario[]> {
  return request<Scenario[]>("/api/scenarios");
}

export function startRun(scenarioId: string): Promise<RunCreated> {
  return request<RunCreated>("/api/runs", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      scenario_id: scenarioId,
    }),
  });
}

export function getRun(runId: string): Promise<Run> {
  return request<Run>(`/api/runs/${encodeURIComponent(runId)}`);
}
