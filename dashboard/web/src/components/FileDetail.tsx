import { useEffect, useState } from "react";

import { fetchPreview } from "../api";
import { displayLevel, droppedPids, fileKey, fileStatus, LEVEL_RANK, shortPath } from "../eventStats";
import { fmtTime } from "../fileStats";
import { describeEvent, isHiddenEvent, rawText, setattrSources, useThresholds } from "../reasonText";
import type { EdrEvent, FileInfo, Preview } from "../types";

interface Props {
  target: string;
  events: EdrEvent[];          // 조회 기간과 상관없이 전체 이벤트에서 이 파일 것만 쓴다
  onBack: () => void;
  onPid: (pid: number) => void; // 접근한 프로세스의 PID 상세로 이동
  file?: FileInfo;              // 실행별 상세에서 연 경우: 지금 파일 상태 (보호 폴더 기준 경로)
}

const STATE_LABEL: Record<string, string> = {
  encrypted: "암호화 의심", ok: "정상", unreadable: "읽기 실패", unknown: "판정 불가", honeypot: "미끼 파일",
};

// 지금 디스크(underlay)에 있는 파일 상태와 앞부분 미리보기. HoldFS 기록이 없어도 보여준다.
function CurrentFile({ file, noEvents }: { file: FileInfo; noEvents: boolean }) {
  const [preview, setPreview] = useState<Preview | null>(null);
  useEffect(() => {
    let alive = true;
    fetchPreview("protected", file.path).then((p) => { if (alive) setPreview(p); });
    return () => { alive = false; };
  }, [file.path]);
  const bad = file.state === "encrypted";
  return (
    <fieldset>
      <legend>현재 파일 상태 · {file.name}</legend>
      <table className="detail-summary">
        <tbody>
          <tr><th>판정</th><th className="num">엔트로피</th><th className="num">크기</th><th>수정</th></tr>
          <tr>
            <td className={bad ? "high" : ""}>{STATE_LABEL[file.state] ?? file.state}</td>
            <td className={`num${bad ? " high" : ""}`}>{file.entropy == null ? "-" : file.entropy.toFixed(2)}</td>
            <td className="num">{file.size.toLocaleString()} B</td>
            <td className="mono">{fmtTime(file.mtime)}</td>
          </tr>
        </tbody>
      </table>
      {noEvents && (
        <p className="caption" style={{ margin: "8px 0 0" }}>
          HoldFS 정책 기록이 없습니다. 차단·보류 없이 LOW 상태로 반영됐거나(이름 변경 포함), 이 파일에는 작업이 없었습니다.
        </p>
      )}
      <p className="caption" style={{ margin: "10px 0 4px" }}>앞부분 미리보기</p>
      <pre className="file-preview">
        {preview === null ? "불러오는 중…"
          : preview.kind === "error" ? "미리보기를 불러오지 못했습니다."
          : preview.content}
      </pre>
    </fieldset>
  );
}

const hms = (t: string) => t.slice(11, 19);   // 밀리초는 정렬에만 쓰고 화면에는 초까지

interface Accessor {
  pid: number;
  process: string;
  level: string;
  count: number;
  result: string;   // 이 프로세스 기록 기준 이 파일 상태
  last: string;
}

export default function FileDetail({ target, events, onBack, onPid, file }: Props) {
  const th = useThresholds();
  const dropped = droppedPids(events);
  // 이름 변경 기록도 원래 파일의 이력으로 함께 보여준다
  const key = fileKey(target);
  const rows = events.filter((e) => e.target && fileKey(e.target) === key && !isHiddenEvent(e))
    .sort((a, b) => a.time.localeCompare(b.time));
  const setattr = setattrSources(rows);
  const last = rows[rows.length - 1];

  // 이 파일에 접근한 프로세스별로 묶는다 (위험도 높은 순)
  const map = new Map<number, Accessor>();
  for (const e of rows) {
    const a = map.get(e.pid) ?? { pid: e.pid, process: e.process, level: "LOW", count: 0, result: "", last: "" };
    a.count += 1;
    if ((LEVEL_RANK[displayLevel(e)] ?? 0) > (LEVEL_RANK[a.level] ?? 0)) a.level = displayLevel(e);
    a.last = e.time;
    map.set(e.pid, a);
  }
  // 접근한 프로세스별 '이 파일 상태'는 그 프로세스의 기록만으로 계산한다
  for (const a of map.values()) a.result = fileStatus(rows.filter((e) => e.pid === a.pid), dropped);
  const accessors = [...map.values()].sort((a, b) =>
    (LEVEL_RANK[b.level] ?? 0) - (LEVEL_RANK[a.level] ?? 0) || b.last.localeCompare(a.last));
  const state = fileStatus(rows, dropped);
  const danger = (s: string) => (s === "차단" ? "high" : "");

  return (
    <>
      <fieldset>
        <legend>파일 상세 · {shortPath(key)}</legend>
        <div className="row-line">
          <button className="btn" onClick={onBack}>‹ 목록으로</button>
          <span className="mono hint" title={key}>{key}</span>
        </div>
        {rows.length === 0 ? (
          !file && <div className="empty" style={{ height: 120 }}>이 파일의 이벤트가 없습니다.</div>
        ) : (
          <table className="detail-summary">
            <tbody>
              <tr>
                <th>현재 상태</th><th className="num">접근한 프로세스</th><th className="num">이벤트</th>
                <th>첫 이벤트</th><th>마지막 이벤트</th>
              </tr>
              <tr>
                <td className={danger(state)}>{state}</td>
                <td className="num">{accessors.length}개</td>
                <td className="num">{rows.length}건</td>
                <td className="mono">{hms(rows[0].time)}</td>
                <td className="mono">{hms(last.time)}</td>
              </tr>
            </tbody>
          </table>
        )}
      </fieldset>

      {file && <CurrentFile file={file} noEvents={rows.length === 0} />}

      {rows.length > 0 && <>
        <fieldset>
          <legend>접근한 프로세스</legend>
          <div className="list" style={{ height: "auto", maxHeight: 220 }}>
            <table>
              <thead><tr><th>PID</th><th>프로세스</th><th>최고 위험도</th><th className="num">이 파일 작업</th><th>이 파일 상태</th><th>상세</th></tr></thead>
              <tbody>
                {accessors.map((a) => (
                  <tr key={a.pid}>
                    <td className="mono">{a.pid}</td>
                    <td>{a.process}</td>
                    <td className={a.level === "HIGH" ? "high" : ""}>{a.level}</td>
                    <td className="num">{a.count}건</td>
                    <td className={danger(a.result)}>{a.result}</td>
                    <td><button className="link-btn" onClick={() => onPid(a.pid)}>PID 상세 ›</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </fieldset>

        <fieldset>
          <legend>파일 이력 ({rows.length}건)</legend>
          <div className="list" style={{ height: 320 }}>
            <table>
              <thead><tr><th>시각</th><th>프로세스</th><th>위험도</th><th>동작</th><th>상세</th></tr></thead>
              <tbody>
                {rows.map((e) => {
                  const d = describeEvent(e, th, setattr.get(e.id));
                  return (
                    <tr key={e.id} title={rawText(e)}>
                      <td className="mono">{hms(e.time)}</td>
                      <td>{e.process} ({e.pid})</td>
                      <td className={displayLevel(e) === "HIGH" ? "high" : ""}>{displayLevel(e)}</td>
                      <td className={displayLevel(e) === "HIGH" ? "high" : ""}>{d.action}</td>
                      <td className="why">{d.detail}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </fieldset>
      </>}
    </>
  );
}
