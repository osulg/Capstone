import type { EdrEvent, FilesResponse, Folder, FolderKey } from "../types";
import FolderTable from "./FolderTable";

interface Props {
  data: FilesResponse | null;
  events: EdrEvent[];
  onFile: (target: string) => void;
}

// 비어 있을 때 안내할 시뮬레이터 실행 경로 (보호 폴더는 마운트를 거쳐야 HoldFS가 개입한다)
const SIM_TARGET: Record<FolderKey, string> = {
  protected: "~/guardfs_runtime/mount/sim_target",
  unprotected: "~/guardfs_demo/unprotected/sim_target",
};

function Summary({ title, folder, kind }: { title: string; folder?: Folder; kind: "kept" | "encrypted" }) {
  const files = (folder?.files ?? []).filter((f) => !f.honeypot);
  const ok = files.filter((f) => f.state === "ok").length;
  const enc = files.filter((f) => f.state === "encrypted").length;
  const honey = (folder?.files ?? []).length - files.length;
  const ext = files.filter((f) => f.ransom_ext).length;
  const main = kind === "kept" ? ok : enc;
  return (
    <div className="result-box">
      <div className="result-title">{title}</div>
      {files.length === 0 ? (
        <div className="result-empty">{folder && !folder.exists ? "폴더가 없습니다." : "파일이 없습니다."}</div>
      ) : <>
        <div className="result-num">
          <b className={kind === "encrypted" && main > 0 ? "bad" : ""}>{main}</b><span> / {files.length}</span>
        </div>
        <div className="result-label">{kind === "kept" ? "원본 유지" : "암호화 의심"}</div>
        <div className="result-sub">
          {kind === "kept"
            ? <>암호화 의심 {enc}{honey > 0 && <> · 미끼 파일 {honey} (별도 집계)</>}</>
            : <>원본 유지 {ok} · 의심 확장자 {ext}</>}
        </div>
      </>}
    </div>
  );
}

export default function CompareView({ data, events, onFile }: Props) {
  const folder = (key: FolderKey) => data?.folders.find((f) => f.key === key);
  const threshold = (data?.threshold ?? 7).toFixed(1);
  return (
    <>
      <fieldset>
        <legend>보호 결과 요약</legend>
        <div className="result-grid">
          <Summary title="보호 폴더 (HoldFS)" folder={folder("protected")} kind="kept" />
          <Summary title="보호 없는 폴더 (비교용)" folder={folder("unprotected")} kind="encrypted" />
        </div>
        <p className="caption" style={{ margin: "10px 0 0" }}>
          같은 공격 시뮬레이터를 두 폴더에 실행한 결과 · 2초마다 갱신 · 판정 기준 엔트로피 {threshold} 이상
        </p>
      </fieldset>

      <div className="grid2 cmp">
        <FolderTable title="보호 폴더 · underlay" folder={folder("protected")} simTarget={SIM_TARGET.protected}
          events={events} onFile={onFile} />
        <FolderTable title="보호 없는 폴더 · 비교용" folder={folder("unprotected")} simTarget={SIM_TARGET.unprotected} />
      </div>
      <p className="caption" style={{ margin: "-4px 0 0" }}>
        보호 없는 폴더는 HoldFS를 거치지 않아 이벤트 기록이 없으므로 상세 화면이 없습니다.
      </p>
    </>
  );
}
