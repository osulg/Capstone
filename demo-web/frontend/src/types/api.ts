export interface ScenarioStep {
  id: string;
  name: string;
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
  error: string | null;
}
