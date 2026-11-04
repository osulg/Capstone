import type {
  ChatResponse, ChatTurn, EventsResponse, FilesResponse, FolderKey, Health, Preview,
} from "./types";

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
  return res.json() as Promise<T>;
}

export const fetchEvents = (sinceId: number, gen: number) =>
  getJson<EventsResponse>(`/api/events?since_id=${sinceId}&gen=${gen}`);

export const fetchHealth = () => getJson<Health>("/api/health");

export const fetchFiles = () => getJson<FilesResponse>("/api/files");

export async function fetchPreview(key: FolderKey, path: string): Promise<Preview> {
  try {
    const res = await fetch(`/api/files/preview?folder=${key}&path=${encodeURIComponent(path)}`);
    return res.ok ? ((await res.json()) as Preview) : { kind: "error" };
  } catch {
    return { kind: "error" };
  }
}

export async function postChat(message: string, history: ChatTurn[]): Promise<ChatResponse> {
  const res = await fetch("/api/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message, history }),
  });
  const data = (await res.json()) as ChatResponse;
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}
