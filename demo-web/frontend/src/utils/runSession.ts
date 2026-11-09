import { isModeForScenario } from "../types/api";
import type { ScenarioRunMode } from "../types/api";

/** 같은 탭에서 새로고침 후 복구할 실행 정보 */
export interface SavedRun {
  runId: string;
  scenarioId: string;
  mode: ScenarioRunMode | null;
}

// 이전 번호 체계의 실행 ID를 다른 시나리오로 복원하지 않는다.
const STORAGE_KEY = "holdfs.demo.savedRun.v2";

export function readSavedRun(): SavedRun | null {
  try {
    const text = sessionStorage.getItem(STORAGE_KEY);
    if (!text) return null;

    const value: unknown = JSON.parse(text);

    if (
      typeof value !== "object" ||
      value === null ||
      !("runId" in value) ||
      !("scenarioId" in value) ||
      typeof value.runId !== "string" ||
      typeof value.scenarioId !== "string" ||
      !value.runId.trim() ||
      !value.scenarioId.trim()
    ) {
      return null;
    }

    const storedMode = "mode" in value ? value.mode : null;

    if (!["S01", "S02", "S03", "S04"].includes(value.scenarioId)) return null;
    if (
      (value.scenarioId === "S02" || value.scenarioId === "S03") &&
      !isModeForScenario(value.scenarioId, storedMode)
    ) return null;

    return {
      runId: value.runId,
      scenarioId: value.scenarioId,
      mode: isModeForScenario(value.scenarioId, storedMode)
        ? storedMode
        : null,
    };
  } catch {
    return null;
  }
}

export function saveRun(value: SavedRun): boolean {
  try {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(value));
    return true;
  } catch {
    return false;
  }
}

export function clearSavedRun(): void {
  try {
    sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    // 저장소 사용 실패가 현재 실행 조회를 중단하지 않게 한다.
  }
}
