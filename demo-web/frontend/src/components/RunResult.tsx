import { useEffect, useState } from "react";
import type { Run } from "../types/api";
import { dashboardUrl } from "../utils/dashboard";

interface RunResultProps {
  run: Run;
}

function durationLabel(run: Run): string {
  if (!run.started_at || !run.finished_at) return "확인되지 않음";

  const milliseconds =
    Date.parse(run.finished_at) - Date.parse(run.started_at);

  if (!Number.isFinite(milliseconds) || milliseconds < 0) {
    return "확인되지 않음";
  }

  return `${(milliseconds / 1000).toFixed(1)}초`;
}

/** 파일 작업 검증, 프로세스 실행 중단, 탐지 검증 결과를 구분해 표시한다. */
export default function RunResult({ run }: RunResultProps) {
  const [copyStatus, setCopyStatus] = useState<{
    runId: string;
    state: "copying" | "copied" | "failed";
  } | null>(null);
  const currentCopyStatus =
    copyStatus?.runId === run.run_id ? copyStatus.state : null;

  useEffect(() => {
    if (copyStatus?.state !== "copied") return;
    const timer = window.setTimeout(() => setCopyStatus(null), 2000);
    return () => window.clearTimeout(timer);
  }, [copyStatus]);

  async function copyJson() {
    const runId = run.run_id;
    setCopyStatus({ runId, state: "copying" });
    try {
      // 화면에 표시하는 전체 실행 응답을 복사한다.
      await navigator.clipboard.writeText(JSON.stringify(run, null, 2));
      setCopyStatus({ runId, state: "copied" });
    } catch {
      setCopyStatus({ runId, state: "failed" });
    }
  }

  const passed = run.status === "passed";
  const cancelled = run.status === "cancelled";
  const completed = run.steps.filter((step) => step.status === "passed").length;
  const protection = run.protection_verification;
  const protectedFiles = protection?.status === "passed";
  const isHoneypot =
    run.scenario_id === "S02" && run.mode === "honeypot";
  const isDelete = run.scenario_id === "S02" && run.mode === "delete";
  const deletion = run.deletion_observation;
  const isAkira = run.scenario_id === "S03";
  const isLolbin = run.scenario_id === "S04";
  const lolbinOutcome = run.result?.worker_outcome;
  const lolbinDenied = isLolbin && lolbinOutcome !== null &&
    typeof lolbinOutcome === "object" && "status" in lolbinOutcome &&
    lolbinOutcome.status === "permission_denied";
  const akira = run.akira_observation;
  const protectedIcefireTimeout =
    run.scenario_id === "S01" && protectedFiles && run.status === "timed_out";
  const policyBlock = run.result?.policy_block;
  // 차단 확인과 자식 회수가 모두 기록된 경우에만 정책 차단 종료로 표시한다.
  const policyBlocked =
    (run.scenario_id === "S01" || isAkira) &&
    policyBlock !== null &&
    typeof policyBlock === "object" &&
    "confirmed" in policyBlock && policyBlock.confirmed === true &&
    "process_reaped" in policyBlock && policyBlock.process_reaped === true;

  // 접근 관찰 완료와 보호 검증 성공을 구분한다.
  const resultSuccess = !cancelled && (
    isHoneypot ? protectedFiles : passed || protectedFiles
  );

  const title = cancelled
    ? "테스트 프로세스 실행을 중단했습니다"
    : isLolbin
      ? passed ? "LOLBin 실행과 파일 상태 관찰을 완료했습니다" : "LOLBin 실행 관찰을 완료하지 못했습니다"
    : policyBlocked
      ? protectedFiles
        ? "공격 차단과 원본 보존을 확인했습니다"
        : "정책 차단을 확인해 공격 실행을 종료했습니다"
    : isAkira
      ? passed
        ? "Akira 파일 작업 관찰을 완료했습니다"
        : run.status === "timed_out"
          ? "Akira 작업 제한 시간을 초과했습니다"
          : "Akira 작업이 완료되기 전에 종료됐습니다"
    : isDelete
      ? passed
        ? "로그 삭제 시도와 파일 상태 관찰을 완료했습니다"
        : run.status === "timed_out"
          ? "로그 삭제 작업의 제한 시간을 초과했습니다"
          : "로그 삭제 작업을 완료하지 못했습니다"
    : isHoneypot
      ? protectedFiles
        ? "허니팟 읽기 접근 차단을 확인했습니다"
        : protection?.status === "failed"
          ? "허니팟 읽기 접근 차단에 실패했습니다"
          : passed
            ? "접근 관찰을 완료했지만 보호 여부는 확인하지 못했습니다"
            : run.status === "timed_out"
              ? "허니팟 접근 관찰 중 제한 시간을 초과했습니다"
              : "허니팟 접근 관찰을 완료하지 못했습니다"
      : protectedFiles
        ? "공격 차단과 원본 보존을 확인했습니다"
        : passed
          ? "파일 작업 검증을 완료했습니다"
          : run.status === "timed_out"
            ? "실행 제한 시간을 초과했습니다"
            : "파일 작업 검증을 완료하지 못했습니다";

  const statusLabel = cancelled
    ? "프로세스 종료"
    : isLolbin
      ? passed ? "작업 관찰 완료" : run.status === "timed_out" ? "시간 초과" : "실행 실패"
    : policyBlocked
      ? protectedFiles ? "보호 검증 완료" : "정책 차단 종료"
    : isAkira
      ? passed ? "작업 관찰 완료" : run.status === "timed_out" ? "시간 초과" : "작업 종료"
    : isDelete
      ? passed
        ? "작업 관찰 완료"
        : run.status === "timed_out"
          ? "시간 초과"
          : "실행 실패"
    : isHoneypot
      ? protectedFiles
        ? "접근 차단 확인"
        : protection?.status === "failed"
          ? "보호 검증 실패"
          : "보호 판정 불가"
      : protectedFiles
        ? "보호 검증 완료"
        : passed
          ? "검증 성공"
          : run.status === "timed_out"
            ? "시간 초과"
            : "검증 실패";

  return (
    <section
      className={`actual-result ${
        cancelled ? "is-cancelled" : resultSuccess ? "is-passed" : policyBlocked ? "is-cancelled" : "is-failed"
      }`}
      aria-labelledby="result-heading"
    >
      <header className="result-heading">
        <div className="result-heading-copy">
          <span className="result-icon" aria-hidden="true">
            {cancelled ? "−" : resultSuccess ? "✓" : policyBlocked ? "−" : "!"}
          </span>
          <div>
            <p className="result-eyebrow">실제 검증 결과</p>
            <h3 id="result-heading">{title}</h3>
          </div>
        </div>
        <span className="result-status">
          {statusLabel}
        </span>
      </header>

      <dl className="result-metrics">
        <div>
          <dt>완료한 단계</dt>
          <dd>{completed}<span> / {run.steps.length}</span></dd>
        </div>
        <div>
          <dt>소요 시간</dt>
          <dd>{durationLabel(run)}</dd>
        </div>
      </dl>

      {isLolbin && (
        <div className="result-note">
          {lolbinDenied && <p>공격 작업의 접근 거부를 관찰하고, 이후 파일 상태를 확인했습니다. 거부 원인이 ML 판단인지는 별도 근거로 확인해야 합니다.</p>}
          <p>작업 관찰 완료는 ML 차단 성공이나 원본 보존 성공을 뜻하지 않습니다.</p>
          <p>상세 JSON의 worker_outcome과 task_results에서 공격 종료·회수 결과와 양쪽 파일 상태를 확인하세요. ML 격상 여부는 공격 PID의 TRIGGER HIGH 사유와 대조합니다.</p>
        </div>
      )}

      {isAkira && (
        <div className="result-policy-note">
          <strong>
            Akira {run.mode === "tail" ? "뒷부분" : "앞부분"} 20%
            {" · 종료 후 파일 상태 "}
            {akira?.status === "observed" ? "확인 완료" : "전체 확인 불가"}
          </strong>
          <p>
            원본과 .akiranew 파일을 각각 확인합니다.
            작업 완료나 시간 초과만으로 보호 성공을 판정하지 않습니다.
          </p>
          {(["mount", "underlay"] as const).map((side) => (
            <p key={side}>
              <strong>{side}</strong>
              {" · 원본 내용 일치 "}
              {akira ? akira.files.filter((file) => file[side].original === "matched").length : "—"}개
              {" · 원본 내용 변경 "}
              {akira ? akira.files.filter((file) => file[side].original === "changed").length : "—"}개
              {" · 이름 변경 파일 발견 "}
              {akira ? akira.files.filter((file) => file[side].renamed === "matched" || file[side].renamed === "changed").length : "—"}개
            </p>
          ))}
          {akira?.issues.map((issue, index) => (
            <p key={`${index}-${issue}`}>{issue}</p>
          ))}
          {akira && akira.files.length > 0 && (
            <details>
              <summary>파일별 상태 보기</summary>
              <ul>
                {akira.files.map((file) => {
                  const labels = {
                    matched: "내용 일치", changed: "내용 변경",
                    missing: "파일 없음", unreadable: "확인 불가",
                  };
                  return (
                    <li key={file.name}>
                      <strong>{file.name}</strong>
                      {(["mount", "underlay"] as const).map((side) => (
                        <p key={side}>
                          {side}{" · 원본: "}{labels[file[side].original]}
                          {" · .akiranew: "}{labels[file[side].renamed]}
                        </p>
                      ))}
                    </li>
                  );
                })}
              </ul>
            </details>
          )}
        </div>
      )}

      {isDelete && (
        <div className="result-policy-note">
          <strong>
            종료 후 파일 상태: {deletion?.status === "observed" ? "확인 완료" : "전체 확인 불가"}
          </strong>
          <p>
            내용 일치는 준비한 더미 로그와의 일치를 뜻합니다.
            파일 없음은 삭제 성공이나 정책 차단 여부를 단독으로 증명하지 않습니다.
          </p>
          {(["mount", "underlay"] as const).map((side) => {
            const counts = deletion?.counts[side];
            return (
              <p key={side}>
                <strong>{side}</strong>
                {" · "}내용 일치 {counts?.matched ?? "—"}개
                {" · "}변경 {counts?.changed ?? "—"}개
                {" · "}파일 없음 {counts?.missing ?? "—"}개
                {" · "}확인 불가 {counts?.unreadable ?? "—"}개
              </p>
            );
          })}
          {deletion?.observed_at && (
            <p>관찰 시각: {new Date(deletion.observed_at).toLocaleString("ko-KR")}</p>
          )}
          {deletion?.issues.map((issue, index) => (
            <p key={`${index}-${issue}`}>{issue}</p>
          ))}
          {deletion && deletion.files.length > 0 && (
            <details>
              <summary>파일별 상태 보기</summary>
              <ul>
                {deletion.files.map((file) => {
                  const labels = {
                    matched: "내용 일치",
                    changed: "변경",
                    missing: "파일 없음",
                    unreadable: "확인 불가",
                  };
                  return (
                    <li key={file.name}>
                      {file.name}{" · mount: "}{labels[file.mount]}
                      {" · underlay: "}{labels[file.underlay]}
                    </li>
                  );
                })}
              </ul>
            </details>
          )}
          <p>작업 관찰 완료는 전체 파일 보존이나 보호 성공을 의미하지 않습니다.</p>
        </div>
      )}

      {protection && (
        <div className="result-policy-note">
          <strong>보호 검증: {protection.status === "passed" ? "완료" : protection.status === "failed" ? "실패" : "판정 불가"}</strong>
          <p>{protection.reason}</p>
          <p>
            {isHoneypot
              ? "등록된 접근 PID와 허니팟 경로의 접근 거부·차단 근거를 확인한 결과입니다. 미끼 내용 보존과 Stage 2 상태 판정은 검증 범위에 포함하지 않습니다."
              : isAkira
                ? "등록된 공격 PID의 차단·회수와 mount·underlay 원본 VM 더미 파일 8개의 내용 일치를 확인한 결과입니다."
              : "관찰 시점의 문서 내용과 차단 근거를 확인한 결과입니다. 후속 지연 작업 완료를 보장하지 않습니다."}
          </p>
        </div>
      )}

      {isHoneypot && passed && (
        <p className="result-note">
          접근 관찰 작업은 완료됐습니다. 보호 성공 여부는 별도의 보호 검증 결과로 확인하세요.
        </p>
      )}

      {cancelled && (
        <p className="result-note">
          테스트가 중단되어 전체 파일 작업 검증을 완료하지 못했습니다.
          완료한 단계 수는 중단 전에 검증을 마친 단계만 집계합니다.
        </p>
      )}

      {/* 실행 중단 완료는 HoldFS 대기 작업의 취소나 처리 완료를 의미하지 않는다. */}
      {cancelled ? (
        <div className="result-policy-note">
          <strong>HoldFS 후속 처리 안내</strong>
          <p>
            이미 접수된 작업은 HoldFS 정책에 따라 이후 반영될 수 있습니다.
            이 중단 요청은 대기 작업을 폐기하거나 파일 변경을 되돌리지 않습니다.
          </p>
          <p>
            최종 반영 내역은{" "}
            <a
              className="dashboard-link"
              href={dashboardUrl()}
              target="_blank"
              rel="noopener noreferrer"
            >
              대시보드 ↗
            </a>
            에서 해당 작업 PID로 확인하세요.
            {run.processes.length > 0 && (
              <>
                {" "}작업 PID:{" "}
                {run.processes.map((process, index) => (
                  <span key={`${process.pid}:${process.start_time_ticks}`}>
                    {index > 0 && ", "}
                    <a
                      className="dashboard-link"
                      href={dashboardUrl(process.pid)}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      {process.pid}
                    </a>
                  </span>
                ))}
              </>
            )}
          </p>
        </div>
      ) : policyBlocked ? (
        <div className="result-policy-note">
          <strong>공격 프로세스 종료·회수 완료</strong>
          <p>
            정지된 공격 PID와 이번 실행 경로의 HIGH 차단 기록을 확인했습니다.
            원본 보존 여부는 별도 파일 상태 결과로 확인하세요.
          </p>
          <p>원래 실행 상태와 차단 근거는 상세 JSON에 유지됩니다.</p>
        </div>
      ) : protectedIcefireTimeout ? (
        <div className="result-policy-note">
          <strong>공격 작업 응답 대기 종료</strong>
          <p>
            공격 작업은 제한 시간 안에 완료 응답을 반환하지 못했습니다.
            별도 보호 검증에서는 차단 근거와 원본 보존을 확인했습니다.
          </p>
          <p>실행 상태와 원래 오류는 상세 JSON에 유지됩니다.</p>
        </div>
      ) : run.error ? (
        <div className="result-error" role="alert">
          <strong>작업 실행 결과: {run.status === "timed_out" ? "시간 초과" : run.status}</strong>
          <p>{run.error}</p>
        </div>
      ) : null}

      {/* 중단 시 result가 없어도 상태와 단계를 확인하도록 전체 응답을 표시한다. */}
      <details className="result-details" key={run.run_id}>
        <summary>
          <span className="result-details-label">
            <span className="result-code-icon" aria-hidden="true">{"{ }"}</span>
            상세 결과 보기
          </span>
          <span className="result-details-end">
            <span className="result-format">JSON</span>
            <span className="result-chevron" aria-hidden="true">⌄</span>
          </span>
        </summary>
        <div className="result-json-header">
          <span>시나리오 실행 결과</span>
          <button
            className="result-copy-button"
            type="button"
            onClick={() => void copyJson()}
            disabled={currentCopyStatus === "copying"}
            aria-label={currentCopyStatus === "copied" ? "JSON 복사 완료" : "JSON 복사"}
            title={currentCopyStatus === "copied" ? "복사 완료" : "JSON 복사"}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              {currentCopyStatus === "copied" ? (
                <path d="m5 12 4 4L19 6" />
              ) : (
                <>
                  <rect x="8" y="8" width="12" height="12" rx="2" />
                  <path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" />
                </>
              )}
            </svg>
          </button>
          <span className={currentCopyStatus === "failed" ? "result-copy-status" : "sr-only"} role="status" aria-live="polite">
            {currentCopyStatus === "copied"
              ? "JSON 복사 완료"
              : currentCopyStatus === "failed"
                ? "복사하지 못했습니다. 아래 JSON을 직접 선택해 복사해주세요."
                : ""}
          </span>
        </div>
        <pre tabIndex={0} aria-label="시나리오 실행 결과 JSON">
          <code>{JSON.stringify(run, null, 2)}</code>
        </pre>
      </details>
    </section>
  );
}
