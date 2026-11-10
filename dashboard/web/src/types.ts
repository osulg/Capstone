export interface EdrEvent {
  id: number;
  time: string;
  level: string;
  pid: number;
  process: string;       // 웹 시연 작업 프로세스는 등록된 역할(lolbin_attack 등)
  comm?: string;         // 역할로 바꾼 경우 원래 프로세스 이름 (python3 등)
  role?: string;
  scenario?: string;
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

// 실행별 로그 조회: 웹 시연 시나리오가 실행마다 만드는 폴더(s01_~s04_<32자리 16진수>)
export interface RunSummary {
  name: string;
  scenario: string;      // "S04"
  label: string;         // "S04 LOLBin"
  total: number;         // 폴더 안 파일 수
  suspect: number;       // 감염 의심(엔트로피 기준 이상) 파일 수. 확장자 변경은 세지 않는다
  ok: number;
  mtime: number;
}

export interface RunsResponse {
  threshold: number;
  root: string;
  exists: boolean;
  runs: RunSummary[];
  truncated: boolean;
}

export interface RunDetailResponse {
  threshold: number;
  root: string;
  folder: FolderKey;     // 미리보기 API에 넘길 폴더 키 (보호 폴더)
  summary: RunSummary;
  files: FileInfo[];     // path 는 보호 폴더 기준 상대경로 ("s04_…/file_000.txt")
  truncated: boolean;
}
