/** 같은 탭에서 새로고침 후 복구할 실행 정보 */
export interface SavedRun {
  runId: string;
  scenarioId: string;
}

const STORAGE_KEY = "holdfs.demo.savedRun.v1";

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

    return {
      runId: value.runId,
      scenarioId: value.scenarioId,
    };
  } catch {
    // 저장 차단이나 손상된 값 때문에 화면 전체를 중단하지 않는다.
    return null;
  }
}

export function saveRun(value: SavedRun): boolean {
  try {
    sessionStorage.setItem(
      STORAGE_KEY,
      JSON.stringify(value),
    );

    return true;
  } catch {
    return false;
  }
}

export function clearSavedRun(): void {
  try {
    sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    // 저장소를 사용할 수 없어도 현재 화면에서는 계속 동작한다.
  }
}
