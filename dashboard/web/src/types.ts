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
