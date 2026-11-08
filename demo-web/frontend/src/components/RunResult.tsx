import type { Run } from "../types/api";

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
  const passed = run.status === "passed";
  const cancelled = run.status === "cancelled";
  const completed = run.steps.filter((step) => step.status === "passed").length;
  const detection = run.detection_verification;
  const protection = run.protection_verification;
  const protectedFiles = protection?.status === "passed";
  const isHoneypot =
    run.scenario_id === "S03" && run.mode === "honeypot";

  // 접근 관찰 완료와 보호 검증 성공을 구분한다.
  const resultSuccess = !cancelled && (
    isHoneypot ? protectedFiles : passed || protectedFiles
  );

  const title = cancelled
    ? "테스트 프로세스 실행을 중단했습니다"
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
        cancelled ? "is-cancelled" : resultSuccess ? "is-passed" : "is-failed"
      }`}
      aria-labelledby="result-heading"
    >
      <header className="result-heading">
        <div className="result-heading-copy">
          <span className="result-icon" aria-hidden="true">
            {cancelled ? "−" : resultSuccess ? "✓" : "!"}
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
        <div>
          <dt>탐지·오탐 검증</dt>
          <dd className={detection === "not_checked" ? "is-muted" : ""}>
            {detection === "not_checked"
              ? "미검증"
              : detection === "passed" ? "성공" : "실패"}
          </dd>
        </div>
      </dl>

      {protection && (
        <div className="result-policy-note">
          <strong>보호 검증: {protection.status === "passed" ? "완료" : protection.status === "failed" ? "실패" : "판정 불가"}</strong>
          <p>{protection.reason}</p>
          <p>
            {isHoneypot
              ? "등록된 접근 PID와 허니팟 경로의 접근 거부·차단 근거를 확인한 결과입니다. 미끼 내용 보존과 Stage 2 상태 판정은 검증 범위에 포함하지 않습니다."
              : "관찰 시점의 문서 내용과 차단 근거를 확인한 결과입니다. 후속 지연 작업 완료나 일반적인 탐지·오탐 성능을 보장하지 않습니다."}
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

      {detection === "not_checked" && (
        <p className="result-note">
          탐지·오탐 여부는 별도로 검증해야 합니다.
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
          <p>최종 반영 내역은 대시보드에서 해당 작업 PID로 확인하세요.</p>
        </div>
      ) : run.error ? (
        <div className="result-error" role="alert">
          <strong>공격 실행 결과: {run.status === "timed_out" ? "시간 초과" : run.status}</strong>
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
        <div className="result-json-header">시나리오 실행 결과</div>
        <pre tabIndex={0} aria-label="시나리오 실행 결과 JSON">
          <code>{JSON.stringify(run, null, 2)}</code>
        </pre>
      </details>
    </section>
  );
}
