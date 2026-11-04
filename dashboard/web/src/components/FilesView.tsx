import { useEffect, useRef, useState } from "react";

import { fetchFiles, fetchPreview } from "../api";
import type { FileInfo, FilesResponse, FolderKey, Preview } from "../types";
import FolderPanel, { hhmmss } from "./FolderPanel";

const FILE_POLL_MS = 2000;
const KEYS: FolderKey[] = ["protected", "unprotected"];

type PerFolder<T> = Partial<Record<FolderKey, T>>;

// 선택 유지. 없으면 암호화 의심 파일 → 첫 파일 순으로 고른다.
function pickSelection(data: FilesResponse, prev: PerFolder<string>): PerFolder<string> {
  const next: PerFolder<string> = {};
  for (const folder of data.folders) {
    const keep = folder.files.find((f) => f.path === prev[folder.key]);
    const sel = keep || folder.files.find((f) => f.state === "encrypted") || folder.files[0];
    next[folder.key] = sel?.path;
  }
  return next;
}

export default function FilesView({ visible }: { visible: boolean }) {
  const [data, setData] = useState<FilesResponse | null>(null);
  const [updated, setUpdated] = useState("불러오는 중…");
  const [selected, setSelected] = useState<PerFolder<string>>({});
  const [previews, setPreviews] = useState<PerFolder<{ key: string; preview: Preview }>>({});
  const loading = useRef<PerFolder<string>>({});

  // 탭이 보일 때만 2초마다 스캔한다.
  useEffect(() => {
    if (!visible) return;
    let alive = true;
    const tick = async () => {
      try {
        const d = await fetchFiles();
        if (!alive) return;
        setData(d);
        setSelected((prev) => pickSelection(d, prev));
        setUpdated(hhmmss(new Date()) + " 갱신");
      } catch {
        if (alive) setUpdated("서버 연결 끊김");
      }
    };
    tick();
    const timer = setInterval(tick, FILE_POLL_MS);
    return () => { alive = false; clearInterval(timer); };
  }, [visible]);

  const selectedFile = (key: FolderKey): FileInfo | undefined =>
    data?.folders.find((f) => f.key === key)?.files.find((f) => f.path === selected[key]);

  // 선택 파일이 바뀌거나 내용(mtime/size)이 바뀌었을 때만 미리보기를 다시 받는다.
  const wanted = KEYS.map((k) => {
    const f = selectedFile(k);
    return f ? `${f.path}|${f.mtime}|${f.size}` : "";
  });
  useEffect(() => {
    KEYS.forEach((k, i) => {
      const pkey = wanted[i];
      const f = selectedFile(k);
      if (!pkey || !f || loading.current[k] === pkey) return;
      loading.current[k] = pkey;
      fetchPreview(k, f.path).then((preview) => {
        if (loading.current[k] === pkey) setPreviews((p) => ({ ...p, [k]: { key: pkey, preview } }));
      });
    });
  }, [wanted.join("\n")]);

  const folder = (key: FolderKey) => data?.folders.find((f) => f.key === key);
  const previewFor = (key: FolderKey) => {
    const p = previews[key];
    const f = selectedFile(key);
    return p && f && p.key.startsWith(f.path + "|") ? p.preview : undefined;
  };
  const select = (key: FolderKey) => (path: string) => setSelected((s) => ({ ...s, [key]: path }));

  return (
    <div className="view" id="view-files" hidden={!visible}>
      <div className="files-head">
        <div>
          <h2>파일 상태</h2>
          <p>VM 안의 폴더를 읽기 전용으로 보여줍니다. 같은 공격을 받은 두 폴더를 비교하세요.</p>
        </div>
        <div className="files-tools">
          <span className="chip">암호화 판정 엔트로피 ≥ <b id="files-threshold">{(data?.threshold ?? 7).toFixed(1)}</b></span>
          <span className="chip" id="files-updated">{updated}</span>
        </div>
      </div>

      <div className="compare">
        <FolderPanel folderKey="protected" className="protected" icon="🛡️" title="보호 폴더 (HoldFS)"
          folder={folder("protected")} selected={selectedFile("protected")} preview={previewFor("protected")}
          onSelect={select("protected")} />
        <FolderPanel folderKey="unprotected" className="unprotected" icon="⚠️" title="보호 없는 폴더"
          folder={folder("unprotected")} selected={selectedFile("unprotected")} preview={previewFor("unprotected")}
          onSelect={select("unprotected")} />
      </div>

      <div className="legend">
        <span><i style={{ background: "#22c55e" }}></i>정상 (엔트로피 &lt; 7.0)</span>
        <span><i style={{ background: "#ef4444" }}></i>암호화 의심 (엔트로피 ≥ 7.0)</span>
        <span><i style={{ background: "#94a3b8" }}></i>막대의 세로선 = 판정 기준 7.0 (최대 8.0)</span>
      </div>
    </div>
  );
}
