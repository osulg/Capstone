import type { FileInfo, Folder, FolderKey, Preview } from "../types";

// 비어 있을 때 안내할 시뮬레이터 실행 경로 (보호 폴더는 마운트를 거쳐야 HoldFS가 개입한다)
const SIM_TARGET: Record<FolderKey, string> = {
  protected: "~/guardfs_runtime/mount/sim_target",
  unprotected: "~/guardfs_demo/unprotected/sim_target",
};

const STATE_LABEL: Record<string, [string, string]> = {
  ok: ["ok", "✅ 정상"],
  encrypted: ["enc", "🔴 암호화 의심"],
  unknown: ["unknown", "판정 불가"],
  honeypot: ["honey", "🍯 미끼 파일"],
  unreadable: ["unknown", "읽기 실패"],
};

const fmtSize = (b: number) =>
  b >= 1048576 ? (b / 1048576).toFixed(1) + " MB" : b >= 1024 ? (b / 1024).toFixed(1) + " KB" : b + " B";
export const hhmmss = (d: Date) =>
  [d.getHours(), d.getMinutes(), d.getSeconds()].map((n) => String(n).padStart(2, "0")).join(":");
const fmtTime = (t: number) => hhmmss(new Date(t * 1000));

interface Props {
  folderKey: FolderKey;
  className: string;
  icon: string;
  title: string;
  folder?: Folder;
  selected?: FileInfo;
  preview?: Preview;
  onSelect: (path: string) => void;
}

function FileRow({ f, selected, onSelect }: { f: FileInfo; selected: boolean; onSelect: () => void }) {
  const [cls, label] = STATE_LABEL[f.state] || STATE_LABEL.unknown;
  const hi = f.state === "encrypted";
  const hp = f.state === "honeypot";
  const ent = f.entropy;
  return (
    <li className={`file-row${hi ? " enc" : ""}${hp ? " honey" : ""}${selected ? " selected" : ""}`} onClick={onSelect}>
      <div className="fname">
        {f.dir && <span className="fdir">{f.dir}/</span>}{f.name}
        {f.ransom_ext && <span className="tag-ext">의심 확장자</span>}
      </div>
      <span className={`fstate ${cls}`}>{label}</span>
      <div>
        <div className={`entbar${hi ? " hi" : ""}${hp ? " honey" : ""}`}>
          <span style={{ width: `${ent == null ? 0 : ((ent / 8) * 100).toFixed(1)}%` }}></span>
        </div>
        <div className="entval">{ent == null ? "샘플 부족" : "엔트로피 " + ent.toFixed(2)}</div>
      </div>
      <div className="fmeta">{fmtSize(f.size)}<br />{fmtTime(f.mtime)}</div>
    </li>
  );
}

export default function FolderPanel({ folderKey, className, icon, title, folder, selected, preview, onSelect }: Props) {
  const files = folder?.files ?? [];
  const count = (s: string) => files.filter((f) => f.state === s).length;
  const ok = count("ok"), enc = count("encrypted"), honey = count("honeypot");

  let listBody;
  if (!folder) {
    listBody = null;
  } else if (!files.length) {
    listBody = folder.exists
      ? <div className="folder-empty">파일이 없습니다. 시뮬레이터를 실행해 보세요.<br />
          <code>{`python3 experiments/simulators/sim_highentropy.py ${SIM_TARGET[folderKey]} --keep`}</code></div>
      : <div className="folder-empty">폴더가 없습니다.<br /><code>mkdir -p {folder.path}</code></div>;
  } else {
    listBody = <>
      {files.map((f) => (
        <FileRow key={f.path} f={f} selected={f.path === selected?.path} onSelect={() => onSelect(f.path)} />
      ))}
      {folder.truncated && <li className="folder-empty">파일이 많아 일부만 표시합니다.</li>}
    </>;
  }

  const desc = preview?.kind === "text" ? "앞부분 텍스트" : preview?.kind === "hex" ? `앞부분 ${preview.bytes} 바이트 (hex)` : "";

  return (
    <section className={`folder ${className}`}>
      <div className="folder-head">
        <div className="folder-icon">{icon}</div>
        <div className="folder-title">
          <h3>{title}</h3>
          <code id={`path-${folderKey}`}>{folder?.path ?? "-"}</code>
        </div>
        <div className="folder-sum" id={`sum-${folderKey}`}>
          {files.length > 0 && <>
            <span className="sum ok">정상 {ok}</span>
            {enc > 0 && <span className="sum bad">암호화 {enc}</span>}
            {honey > 0 && <span className="sum honey" title="정상/암호화 개수에서 제외">미끼 {honey}</span>}
          </>}
        </div>
      </div>
      <ul className="file-list" id={`list-${folderKey}`}>{listBody}</ul>
      <div className="preview" id={`preview-${folderKey}`}>
        {selected && preview && <>
          <div className="preview-head"><span>미리보기 · <b>{selected.path}</b></span><span>{desc}</span></div>
          <pre className={preview.kind === "hex" ? "hex" : ""}>
            {preview.kind === "error" ? "미리보기를 불러오지 못했습니다." : preview.content}
          </pre>
        </>}
      </div>
    </section>
  );
}
