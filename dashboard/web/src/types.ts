export interface EdrEvent {
  id: number;
  time: string;
  level: string;
  pid: number;
  process: string;
  target: string;
  action: string;
  result: string;
  reason: string;
}

export interface EventStats {
  total: number;
  high: number;
  medium: number;
  blocked: number;
}

export interface EventsResponse {
  events: EdrEvent[];
  stats: EventStats;
  reset: boolean;
  gen: number;
  last_id: number;
}

export interface Health {
  ok: boolean;
  llm: boolean;
  model: string;
  medium_timeout_sec?: number;   // MEDIUM 관찰 시간 (보류 쓰기 반영까지)
  high_threshold?: number;       // HIGH 격상 가중 점수 기준 (config.STAGE2_HIGH_THRESHOLD)
  dyn_only_threshold?: number;   // 동적 점수 단독 HIGH 기준 (config.STAGE2_DYN_ONLY_HIGH_THRESHOLD)
}

export interface ChatTurn {
  role: "user" | "assistant";
  content: string;
}

export interface ChatResponse {
  reply: string;
  mode: "llm" | "local";
  sources?: { pids?: number[]; docs?: string[]; events?: number };
  error?: string;
}

export type FileState = "ok" | "encrypted" | "unknown" | "honeypot" | "unreadable";

export interface FileInfo {
  path: string;
  name: string;
  dir: string;
  size: number;
  mtime: number;
  entropy: number | null;
  state: FileState;
  ransom_ext: boolean;
  honeypot: boolean;
}

export type FolderKey = "protected" | "unprotected";

export interface Folder {
  key: FolderKey;
  label: string;
  path: string;
  exists: boolean;
  files: FileInfo[];
  truncated: boolean;
}

export interface FilesResponse {
  threshold: number;
  folders: Folder[];
}

export type Preview =
  | { kind: "text"; path: string; content: string }
  | { kind: "hex"; path: string; content: string; bytes: number }
  | { kind: "error" };

export interface SystemStatus {
  holdfs: { running: boolean; pid: number | null };
  mount: { mounted: boolean; path: string };
  agent: { running: boolean; pid: number | null };
  llm: { connected: boolean; model: string };
  protected: boolean;
}
