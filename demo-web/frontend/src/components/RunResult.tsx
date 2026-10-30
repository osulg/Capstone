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

/** 파일 작업 결과와 탐지 검증 결과를 별도로 표시한다. */
export default function RunResult({ run }: RunResultProps) {
  const passed = run.status === "passed";
  const completed = run.steps.filter((step) => step.status === "passed").length;
  const detection = run.detection_verification;

  const title = passed
    ? "파일 작업 검증을 완료했습니다"
    : run.status === "timed_out"
      ? "실행 제한 시간을 초과했습니다"
      : "파일 작업 검증을 완료하지 못했습니다";

  return (
    <section
      className={`actual-result ${passed ? "is-passed" : "is-failed"}`}
      aria-labelledby="result-heading"
    >
      <header className="result-heading">
        <div className="result-heading-copy">
          <span className="result-icon" aria-hidden="true">
            {passed ? "✓" : "!"}
          </span>
          <div>
            <p className="result-eyebrow">실제 검증 결과</p>
            <h3 id="result-heading">{title}</h3>
          </div>
        </div>
        <span className="result-status">
          {passed ? "검증 성공" : run.status === "timed_out" ? "시간 초과" : "검증 실패"}
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

      {detection === "not_checked" && (
        <p className="result-note">
          이 결과는 파일 작업에 대한 검증입니다. 탐지·오탐 여부는 별도로 검증해야 합니다.
        </p>
      )}

      {run.error && (
        <div className="result-error" role="alert">
          <strong>오류 내용</strong>
          <p>{run.error}</p>
        </div>
      )}

      {/* PID와 실행 ID는 위의 실행 정보 영역에서 확인한다. */}
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
          <code>{JSON.stringify(run.result, null, 2)}</code>
        </pre>
      </details>
    </section>
  );
}
