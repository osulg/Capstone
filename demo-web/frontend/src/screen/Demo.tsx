import { useEffect, useRef, useState } from "react";

import { getRun, getScenarios, startRun } from "../api/clients";
import type {
  Run,
  RunStatus,
  RunStep,
  Scenario,
  StepStatus,
} from "../types/api";

/** 이 상태에 도달하면 반복 조회를 종료한다. */
const TERMINAL_STATUSES: RunStatus[] = [
  "passed",
  "failed",
  "timed_out",
];

const RUN_LABELS: Record<RunStatus, string> = {
  queued: "실행 대기",
  running: "실행 중",
  passed: "파일 작업 검증 성공",
  failed: "검증 실패",
  timed_out: "시간 초과",
};

const STEP_LABELS: Record<StepStatus, string> = {
  pending: "대기",
  running: "실행 중",
  passed: "완료",
  failed: "실패",
  skipped: "수행하지 않음",
};

function isFinished(status: RunStatus): boolean {
  return TERMINAL_STATUSES.includes(status);
}

function errorMessage(error: unknown): string {
  return error instanceof Error
    ? error.message
    : "알 수 없는 오류가 발생했습니다.";
}

interface DemoProps {
  /** 인트로 화면 구현 후 App에서 전달할 화면 전환 함수 */
  onReplayIntro?: () => void;
}

export default function Demo({ onReplayIntro }: DemoProps) {
  // ── 시나리오 목록과 선택 상태 ──
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [selectedId, setSelectedId] = useState("S01");
  const [loading, setLoading] = useState(true);
  const [listError, setListError] = useState("");
  const [listRetry, setListRetry] = useState(0);

  // ── 실행 요청 상태 ──
  const [submitting, setSubmitting] = useState(false);
  const [startError, setStartError] = useState("");

  // 응답을 받지 못한 POST는 서버에서 실행됐을 수 있다.
  // 자동 재실행을 막고 서버 확인이 필요하다는 상태로 유지한다.
  const [startUncertain, setStartUncertain] = useState(false);

  // state 반영 전 빠른 연속 클릭도 차단한다.
  const submittingRef = useRef(false);

  // ── 현재 실행과 결과 조회 상태 ──
  const [runId, setRunId] = useState<string | null>(null);
  const [run, setRun] = useState<Run | null>(null);
  const [pollError, setPollError] = useState("");
  const [pollRetry, setPollRetry] = useState(0);

  const selected = scenarios.find((item) => item.id === selectedId);

  // 조회가 실패해도 실제 테스트가 종료됐다고 가정하지 않는다.
  const awaitingResult =
    runId !== null && (run === null || !isFinished(run.status));

  const busy = submitting || awaitingResult || startUncertain;

  // ── 1. 화면 진입 및 재시도 시 시나리오 목록 조회 ──
  useEffect(() => {
    let ignore = false;

    setLoading(true);
    setListError("");

    getScenarios()
      .then((items) => {
        if (ignore) return;

        setScenarios(items);
        setSelectedId((prev) => {
          const existing = items.find((item) => item.id === prev);

          return (
            existing?.id ??
            items.find((item) => item.enabled)?.id ??
            items[0]?.id ??
            ""
          );

        });
      })
      .catch((error: unknown) => {
        if (!ignore) setListError(errorMessage(error));
      })
      .finally(() => {
        if (!ignore) setLoading(false);
      });

    return () => {
      // 늦게 도착한 이전 응답의 화면 반영을 막는다.
      ignore = true;
    };
  }, [listRetry]);

  // ── 2. 실행 ID가 생기면 해당 실행의 결과 반복 조회 ──
  useEffect(() => {
    if (!runId) return;

    const currentRunId = runId;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    setPollError("");

    async function poll() {
      try {
        const result = await getRun(currentRunId);

        if (stopped) return;

        setRun(result);

        // 이전 요청이 끝난 다음에만 다음 조회를 예약한다.
        if (!isFinished(result.status)) {
          timer = setTimeout(poll, 500);
        }
      } catch (error: unknown) {
        if (!stopped) {
          // 조회 실패와 실제 테스트 실패는 별개다.
          setPollError(errorMessage(error));
        }
      }
    }

    void poll();

    return () => {
      stopped = true;
      if (timer !== undefined) clearTimeout(timer);
    };
  }, [runId, pollRetry]);

  // ── 3. 시나리오 선택 ──
  function selectScenario(id: string) {
    if (busy || id === selectedId) return;

    setSelectedId(id);
    setRunId(null);
    setRun(null);
    setStartError("");
    setPollError("");
  }

  // ── 4. 사용자가 버튼을 눌렀을 때만 실행 요청 ──
  async function handleStart() {
    if (!selected?.enabled || busy || submittingRef.current) return;

    submittingRef.current = true;
    setSubmitting(true);
    setStartError("");

    try {
      const created = await startRun(selected.id);

      setRun(null);
      setPollError("");
      setRunId(created.run_id);
    } catch (error: unknown) {
      setStartError(errorMessage(error));

      // 현재 API 클라이언트는 HTTP 오류와 전송 오류를 구분하지 않는다.
      // 보수적으로 중복 POST를 막고 서버 상태를 먼저 확인하도록 한다.
      setStartUncertain(true);
    } finally {
      submittingRef.current = false;
      setSubmitting(false);
    }
  }

  // 실행 전에는 카탈로그 단계, 실행 후에는 서버 결과 단계를 표시한다.
  const steps: RunStep[] =
    run?.steps ??
    selected?.steps.map((step) => ({
      ...step,
      status: "pending" as StepStatus,
      error: null,
    })) ??
    [];

  // 서버가 완료했다고 확인한 단계만 진행률에 반영한다.
  // 네 단계라면 완료 시 25% → 50% → 75% → 100%가 된다.
  const completed = steps.filter((step) => step.status === "passed").length;
  const progress = steps.length > 0 ? (completed / steps.length) * 100 : 0;

  const badgeText = startUncertain
    ? "서버 확인 필요"
    : submitting
      ? "요청 중"
      : pollError
        ? "조회 확인 필요"
        : run
          ? RUN_LABELS[run.status]
          : runId
            ? "상태 확인 중"
            : selected?.enabled
              ? "준비됨"
              : "준비 중";

  const badgeTone =
    run?.status === "passed"
      ? "success"
      : run?.status === "failed" || run?.status === "timed_out"
        ? "error"
        : "neutral";

  return (
    <main className="demo-page">
      <article className="demo-card">
        {/* 상단 브랜드와 인트로 이동 버튼 */}
        <header className="demo-header">
          <div>
            <div className="demo-brand">
              <svg
                viewBox="0 0 24 24"
                width={23}
                height={23}
                fill="none"
                stroke="currentColor"
                strokeWidth={1.6}
                aria-hidden="true"
                >
                  <path d="M12 3 5 6v6c0 4 3 7 7 9 4-2 7-5 7-9V6l-7-3Z" />
                </svg>
                <span>HoldFS</span>
            </div>
            <p className="demo-subtitle">Scenario Test Center</p>
          </div>

          <div className="demo-header-actions">
            <button
              type="button"
              className="demo-intro-button"
              onClick={onReplayIntro}
              disabled={!onReplayIntro || busy}
              title={
                onReplayIntro
                  ? "인트로 화면으로 이동"
                  : "인트로 화면은 추후 연결됩니다."
              }
            >
              Intro
            </button>
            <span className="demo-tag">Demo</span>
          </div>
        </header>

        <div className="demo-content">
          <section aria-labelledby="scenario-heading">
            <h1 id="scenario-heading">테스트 시나리오 선택</h1>
            <p className="demo-muted">
              검증하고 싶은 시나리오를 하나 선택해 주세요.
            </p>

            {loading && <p role="status">목록을 불러오는 중입니다.</p>}

            {listError && (
              <div className="demo-notice error" role="alert">
                <p>목록 조회 실패: {listError}</p>
                <button
                  type="button"
                  disabled={busy || loading}
                  onClick={() => setListRetry((value) => value + 1)}
                >
                  다시 불러오기
                </button>
              </div>
            )}

            {!loading && !listError && scenarios.length === 0 && (
              <p>등록된 시나리오가 없습니다.</p>
            )}

            {/* 미구현 시나리오도 설명은 볼 수 있지만 실행은 차단한다. */}
            <fieldset
              className="scenario-list"
              disabled={busy || loading}
            >
              <legend className="sr-only">시나리오 선택</legend>
              {scenarios.map((scenario) => (
                <label
                  key={scenario.id}
                  className={`scenario-option ${
                    selectedId === scenario.id ? "is-selected" : ""
                  }`}
                >
                  <input
                    type="radio"
                    name="scenario"
                    value={scenario.id}
                    checked={selectedId === scenario.id}
                    onChange={() => selectScenario(scenario.id)}
                  />

                  <span className="scenario-copy">
                    <strong>
                      {scenario.id}. {scenario.name}
                    </strong>
                    <span>{scenario.category}</span>
                  </span>

                  {!scenario.enabled && (
                    <span className="scenario-unavailable">준비 중</span>
                  )}

                  <span className="scenario-check" aria-hidden="true">
                    {selectedId === scenario.id ? "✓" : ""}
                  </span>
                </label>
              ))}
            </fieldset>
          </section>

          {selected && (
            <section className="scenario-detail" aria-labelledby="detail-heading">
              <div className="scenario-detail-heading">
                <h2 id="detail-heading">{selected.name}</h2>
                <span
                  className={`run-badge ${badgeTone}`}
                  role="status"
                >
                  <span aria-hidden="true">●</span>
                  {badgeText}
                </span>
              </div>

              <p className="demo-muted">{selected.description}</p>

              <progress
                className="demo-progress"
                value={progress}
                max={100}
                aria-label="검증 완료 단계 비율"
              />

              {awaitingResult && (
                <p className="demo-caption" role="status">
                  파일 작업 및 지연 반영을 확인하고 있습니다.
                  완료된 단계부터 진행 상태가 갱신됩니다.
                </p>
              )}

              <ol className="run-steps">
                {steps.map((step, index) => (
                  <li key={step.id} className={`run-step ${step.status}`}>
                    <span className="step-number" aria-hidden="true">
                      {step.status === "passed" ? "✓" : index + 1}
                    </span>
                    <div>
                      <strong>{step.name}</strong>
                      <span>{STEP_LABELS[step.status]}</span>
                      {step.error && (
                        <p className="step-error">{step.error}</p>
                      )}
                    </div>
                  </li>
                ))}
              </ol>

              {!selected.enabled && (
                <p className="demo-notice">
                  {selected.disabled_reason ?? "실행 기능을 준비 중입니다."}
                </p>
              )}

              <div className="demo-footer">
                <div className="expected-result">
                  <h3>예상 검증 결과</h3>
                  <p>{selected.expected_result}</p>
                </div>

                <button
                  type="button"
                  className="demo-start-button"
                  disabled={busy || loading || !selected.enabled}
                  onClick={() => void handleStart()}
                >
                  <span>
                    {startUncertain
                      ? "서버 상태 확인 필요"
                      : submitting
                        ? "실행 요청 중"
                        : awaitingResult
                          ? "검증 진행 중"
                          : run
                            ? "다시 실행"
                            : "시연 시작"}
                  </span>
                  <span aria-hidden="true">→</span>
                </button>
              </div>

              {startError && (
                <div className="demo-notice error" role="alert">
                  <p>실행 요청 오류: {startError}</p>
                  <p>
                    서버에서 실행됐을 가능성이 있어 재실행을 잠갔습니다.
                    API 서버 로그와 실행 상태를 확인해 주세요.
                  </p>
                </div>
              )}

              {pollError && (
                <div className="demo-notice error" role="alert">
                  <p>상태 조회 실패: {pollError}</p>
                  <p>실제 테스트 실패를 의미하지 않습니다.</p>
                  <button
                    type="button"
                    onClick={() => setPollRetry((value) => value + 1)}
                  >
                    같은 실행 다시 조회
                  </button>
                </div>
              )}
            </section>
          )}

          {/* 파일 작업 성공을 탐지·오탐 검증 성공과 구분한다. */}
          {run && isFinished(run.status) && (
            <div className="actual-result">
              <h3>실제 검증 결과</h3>
              <p>{RUN_LABELS[run.status]}</p>
              <p>
                탐지·오탐 검증:{" "}
                    {run.detection_verification === "not_checked"
                      ? "아직 검증하지 않음"
                      : run.detection_verification === "passed"
                        ? "성공"
                        : "실패"}
              </p>

              {run.error && (
                <p className="step-error" role="alert">{run.error}</p>
              )}

              <details>
                <summary>실행 정보 및 상세 결과</summary>
                <p>실행 ID: {run.run_id}</p>
                <p>테스트 PID: {run.pid ?? "확인되지 않음"}</p>
                <p>HoldFS PID: {run.holdfs_pid ?? "확인되지 않음"}</p>
                <pre>{JSON.stringify(run.result, null, 2)}</pre>
              </details>
            </div>
          )}

          <p className="demo-caption demo-disclaimer">
                시연 시작 시 연결된 테스트 환경에서 실제 파일 작업이 수행됩니다.
                테스트 전용 데이터와 경로를 사용하세요.
          </p>
        </div>
      </article>
    </main>
  );
}
