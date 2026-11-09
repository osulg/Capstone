export interface ScenarioStep {
  id: string;
  name: string;
}

export type HuntressMode = "read" | "honeypot" | "delete";
export type AkiraMode = "head" | "tail";

export type ScenarioRunMode = HuntressMode | AkiraMode;

export function isModeForScenario(
  scenarioId: string,
  value: unknown,
): value is ScenarioRunMode {
  if (scenarioId === "S02") {
    return isHuntressMode(value);
  }

  return scenarioId === "S03" && (value === "head" || value === "tail");
}

export function isHuntressMode(value: unknown): value is HuntressMode {
  return value === "read" || value === "honeypot" || value === "delete";
}

export interface ScenarioMode {
  id: ScenarioRunMode;
  name: string;
  enabled: boolean;
  disabled_reason: string | null;
  steps: ScenarioStep[];
}

export interface Scenario {
  id: string;
  name: string;
  category: string;
  description: string;
  expected_result: string;
  enabled: boolean;
  disabled_reason: string | null;
  steps: ScenarioStep[];
  modes: ScenarioMode[];
}

export type RunStatus =
  | "queued"
  | "running"
  | "cancelling"
  | "passed"
  | "failed"
  | "timed_out"
  | "cancelled";

export type StepStatus =
  | "pending"
  | "running"
  | "passed"
  | "failed"
  | "skipped";

export interface RunCreated {
  run_id: string;
  scenario_id: string;
  status: RunStatus;
  mode: ScenarioRunMode | null;
}

export interface RunStep extends ScenarioStep {
  status: StepStatus;
  error: string | null;
}

export interface RunProcess {
  role: string;
  pid: number;
  start_time_ticks: number | null;
  registered_at: string;
}

export type FileObservationState =
  | "matched"
  | "changed"
  | "missing"
  | "unreadable";

export interface DeletionObservation {
  status: "observed" | "unknown";
  observed_at?: string | null;
  cleanup_confirmed?: boolean;
  files: {
    name: string;
    mount: FileObservationState;
    underlay: FileObservationState;
  }[];
  counts: Partial<
    Record<
      "mount" | "underlay",
      Record<FileObservationState, number>
    >
  >;
  issues: string[];
  scope?: string;
}

export interface Run extends RunCreated {
  pid: number | null;
  holdfs_pid: number | null;
  processes: RunProcess[];
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  steps: RunStep[];
  result: Record<string, unknown> | null;
  detection_verification: "not_checked" | "passed" | "failed";
  protection_verification?: {
    status: "passed" | "failed" | "unknown";
    reason: string;
    observed_at?: string;
  } | null;
  error: string | null;
  deletion_observation?: DeletionObservation | null;
  akira_observation?: {
    status: "observed" | "unknown";
    observed_at?: string | null;
    cleanup_confirmed?: boolean;
    files: {
      name: string;
      mount: {
        original: FileObservationState;
        renamed: FileObservationState;
      };
      underlay: {
        original: FileObservationState;
        renamed: FileObservationState;
      };
    }[];
    issues: string[];
  } | null;
}
