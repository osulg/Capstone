import { useEffect, useRef, useState } from "react";
import type { CSSProperties } from "react";

import {
  ApiError,
  cancelRun,
  getRun,
  getScenarios,
  startRun,
} from "../api/clients";

import type {
  ScenarioRunMode,
  Run,
  RunStatus,
  RunStep,
  Scenario,
  StepStatus,
} from "../types/api";

import { isModeForScenario } from "../types/api";
import { getRunPresentation } from "../utils/runPresentation";

import {
  clearSavedRun,
  readSavedRun,
  saveRun,
} from "../utils/runSession";

import RunInfo from "../components/RunInfo";
import RunResult from "../components/RunResult";

/** 이 상태에 도달하면 반복 조회를 종료한다. */
const TERMINAL_STATUSES: RunStatus[] = [
  "passed",
  "failed",
  "timed_out",
  "cancelled",
];

const STEP_LABELS: Record<StepStatus, string> = {
  pending: "대기",
  running: "실행 중",
  passed: "완료",
  failed: "실패",
  skipped: "검증하지 못함",
};

const MODE_DESCRIPTIONS: Record<ScenarioRunMode, string> = {
  read: "더미 자격 파일 6개를 읽고 내용 변화를 확인합니다.",
  honeypot: "미리 배치한 미끼에 접근하고 차단 근거를 확인합니다.",
  delete: "더미 로그 12개 삭제를 시도하고 남은 파일을 확인합니다.",
  head: "더미 VM 파일 앞부분 20%를 덮어쓰고 확장자 변경을 시도합니다.",
  tail: "더미 VM 파일 뒷부분 20%를 덮어쓰고 확장자 변경을 시도합니다.",
};

const MODE_CONDITIONS: Record<ScenarioRunMode, string> = {
  read: "더미 자격 파일 6개 · 전체 1회 읽기",
  honeypot: "미끼 5개 사전 준비 · 경로별 접근 시도",
  delete: "더미 로그 12개 · 삭제 간격 0.1초",
  head: "VM 더미 8개 × 64KB · 앞부분 20% · 작업 제한 30초",
  tail: "VM 더미 8개 × 64KB · 뒷부분 20% · 작업 제한 30초",
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
  // 같은 탭의 새로고침에서는 저장된 실행 ID로 조회를 재개한다.
  const [savedRun] = useState(readSavedRun);
  const [sessionNotice, setSessionNotice] = useState("");

  // ── 시나리오 목록과 선택 상태 ──
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [selectedId, setSelectedId] = useState(
    savedRun?.scenarioId ?? "S01",
  );
  const [selectedMode, setSelectedMode] = useState<ScenarioRunMode>(
    savedRun?.mode ?? "read",
  );
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
  const [runId, setRunId] = useState<string | null>(
    savedRun?.runId ?? null,
  );
  const [run, setRun] = useState<Run | null>(null);
  const [pollError, setPollError] = useState("");
  const [pollRetry, setPollRetry] = useState(0);

  // ── 테스트 프로세스 중단 요청 상태 ──
  const [cancelSubmitting, setCancelSubmitting] = useState(false);
  const [cancelAcknowledged, setCancelAcknowledged] = useState(false);
  const [cancelError, setCancelError] = useState("");

  // state 반영 전 연속 클릭도 차단한다.
  const cancelSubmittingRef = useRef(false);

  // 확인 응답을 받았더라도 최종 완료 상태는 GET으로 확인한다.
  const cancellationPending =
    cancelSubmitting ||
    (cancelAcknowledged &&
      runId !== null &&
      (run === null || !isFinished(run.status))) ||
    run?.status === "cancelling";

  const selected = scenarios.find((item) => item.id === selectedId);
  const hasModes = selected?.id === "S03" || selected?.id === "S04";
  const selectedModeDefinition =
    hasModes
      ? (selected.modes ?? []).find((mode) => mode.id === selectedMode)
      : undefined;
  const modeUnavailable =
    hasModes && selectedModeDefinition?.enabled !== true;

  // 조회가 실패해도 실제 테스트가 종료됐다고 가정하지 않는다.
  const awaitingResult =
    runId !== null && (run === null || !isFinished(run.status));

  const busy = submitting || awaitingResult || startUncertain || cancelSubmitting;

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

        // 저장값보다 서버가 반환한 실제 실행 정보를 우선한다.
        setSelectedId(result.scenario_id);
        if (isModeForScenario(result.scenario_id, result.mode)) {
          setSelectedMode(result.mode);
        }
        saveRun({
          runId: result.run_id,
          scenarioId: result.scenario_id,
          mode:
            isModeForScenario(result.scenario_id, result.mode)
              ? result.mode
              : null,
        });

        // 이전 요청이 끝난 다음에만 다음 조회를 예약한다.
        if (!isFinished(result.status)) {
          timer = setTimeout(poll, 500);
        }
      } catch (error: unknown) {
        if (stopped) return;

        if (error instanceof ApiError && error.status === 404) {
          // 서버에서 사라진 조회 기록을 정리한다.
          // 기록이 없다는 응답이 작업 프로세스의 종료를 보장하지는 않는다.
          clearSavedRun();
          setRunId(null);
          setRun(null);
          setPollError("");
          setCancelAcknowledged(false);
          setCancelError("");
          setSessionNotice(
            "이전 실행 기록을 찾을 수 없습니다. " +
              "서버가 재시작되었을 수 있습니다. " +
              "이 메시지가 작업 프로세스의 종료를 의미하지는 않습니다.",
          );
          return;
        }

        // 연결 오류에서는 ID를 유지하고 같은 실행을 다시 조회한다.
        setPollError(errorMessage(error));
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

    clearSavedRun();
    setSelectedId(id);
    setSelectedMode(id === "S04" ? "head" : "read");
    setRunId(null);
    setRun(null);
    setStartError("");
    setPollError("");
    setSessionNotice("");
    setCancelAcknowledged(false);
    setCancelError("");
  }

  function selectMode(value: string) {
    if (
      busy ||
      !isModeForScenario(selectedId, value) ||
      value === selectedMode
    ) return;

    clearSavedRun();
    setSelectedMode(value);
    setRunId(null);
    setRun(null);
    setStartError("");
    setPollError("");
    setSessionNotice("");
    setCancelAcknowledged(false);
    setCancelError("");
  }

  // ── 4. 사용자가 버튼을 눌렀을 때만 실행 요청 ──
  async function handleStart() {
    if (!selected?.enabled || modeUnavailable || busy || submittingRef.current) return;

    submittingRef.current = true;
    setSubmitting(true);
    setStartError("");

    try {
      const mode = selected.id === "S03" || selected.id === "S04" ? selectedMode : null;
      const created = await startRun(selected.id, mode);

      const stored = saveRun({
        runId: created.run_id,
        scenarioId: created.scenario_id,
        mode: created.mode ?? null,
      });

      setSessionNotice(
        stored
          ? ""
          : "브라우저에 실행 정보를 저장하지 못했습니다. " +
              "현재 실행은 조회할 수 있지만, 새로고침 후 자동 복원은 사용할 수 없습니다.",
      );
      setRun(null);
      setPollError("");
      setRunId(created.run_id);
      setCancelAcknowledged(false);
      setCancelError("");
    } catch (error: unknown) {
      setStartError(errorMessage(error));

      // 기존의 보수적인 중복 실행 방지 정책을 유지한다.
      // 응답을 받지 못한 POST의 실행 ID 복구는 별도 기능이 필요하다.
      setStartUncertain(true);
    } finally {
      submittingRef.current = false;
      setSubmitting(false);
    }
  }

  // ── 5. 테스트 프로세스 종료 요청: HoldFS 대기 작업은 취소하지 않는다. ──
  async function handleCancel() {
    if (
      !runId ||
      !run ||
      !["queued", "running"].includes(run.status) ||
      cancellationPending ||
      cancelSubmittingRef.current
    ) {
      return;
    }

    const currentRunId = runId;

    cancelSubmittingRef.current = true;
    setCancelSubmitting(true);
    setCancelError("");

    try {
      const result = await cancelRun(currentRunId);

      setCancelAcknowledged(
        result.status === "cancelling" || result.status === "cancelled",
      );

      // POST 응답으로 화면 상태를 덮어쓰지 않는다.
      // 기존 GET과 응답 순서가 뒤바뀌더라도 최신 상태를 다시 확인한다.
    } catch (error: unknown) {
      setCancelError(
        `프로세스 종료 요청 결과를 확인하지 못했습니다: ${errorMessage(error)}. ` +
          "서버에서 처리됐을 수 있어 같은 실행을 다시 조회합니다.",
      );
    } finally {
      cancelSubmittingRef.current = false;
      setCancelSubmitting(false);

      // 성공·실패 모두 기존 조회를 재시작한다.
      // 조회가 이전에 중단됐던 경우에도 복구할 수 있다.
      setPollRetry((value) => value + 1);
    }
  }

  // 실행 전에는 선택 모드의 단계를 표시한다.
  // 모드 전용 단계가 없으면 기존 시나리오 단계를 사용한다.
  const previewSteps =
    selectedModeDefinition?.steps?.length
      ? selectedModeDefinition.steps
      : selected?.steps ?? [];

  // 실행 후에는 서버에 기록된 실제 단계가 기준이다.
  const steps: RunStep[] =
    run?.steps ??
    previewSteps.map((step) => ({
      ...step,
      status: "pending" as StepStatus,
      error: null,
    }));

  // 서버가 완료했다고 확인한 단계만 진행률에 반영한다.
  // 네 단계라면 완료 시 25% → 50% → 75% → 100%가 된다.
  const completed = steps.filter((step) => step.status === "passed").length;
  const progress = steps.length > 0 ? (completed / steps.length) * 100 : 0;

  const presentation = run ? getRunPresentation(run) : null;

  const badgeText = startUncertain
    ? "서버 확인 필요"
    : submitting
      ? "요청 중"
      : pollError
        ? "조회 확인 필요"
        : presentation
          ? presentation.label
          : runId
            ? "상태 확인 중"
            : selected?.enabled
              ? "준비됨"
              : "준비 중";

  const badgeTone = presentation?.tone ?? "neutral";

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
          {sessionNotice && (
            <div className="demo-notice" role="status">
              {sessionNotice}
            </div>
          )}

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
                  disabled={loading}
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
                <div
                  key={scenario.id}
                  className={`scenario-group ${(scenario.id === "S03" || scenario.id === "S04") && selectedId === scenario.id ? "is-expanded" : ""}`}
                >
                <label
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
                {(scenario.id === "S03" || scenario.id === "S04") && selectedId === scenario.id && (
                  <div className="huntress-panel">
                    <fieldset className="huntress-tabs">
                      <legend className="sr-only">{scenario.name} 실행 모드</legend>
                      {(scenario.modes ?? []).filter((mode) => mode.id !== "delete").map((mode) => (
                        <label
                          key={mode.id}
                          className={`huntress-tab ${selectedMode === mode.id ? "is-selected" : ""}`}
                        >
                          <input
                            type="radio"
                            name={`scenario-mode-${scenario.id}`}
                            value={mode.id}
                            checked={selectedMode === mode.id}
                            onChange={() => selectMode(mode.id)}
                          />
                          <span>{mode.id === "read" ? "일반 읽기" : mode.id === "honeypot" ? "허니팟 접근" : mode.name}</span>
                        </label>
                      ))}
                    </fieldset>
                    <div className="huntress-mode-detail">
                      <h3>{scenario.modes?.find((mode) => mode.id === selectedMode)?.name}</h3>
                      <p>{MODE_DESCRIPTIONS[selectedMode]}</p>
                      <dl>
                        <div>
                          <dt>실행 조건</dt>
                          <dd>{MODE_CONDITIONS[selectedMode]}</dd>
                        </div>
                        <div>
                          <dt>확인 범위</dt>
                          <dd>{selectedMode === "read" ? "읽기 결과와 내용 불변" : selectedMode === "honeypot" ? "접근 결과와 차단 근거" : selectedMode === "delete" ? "삭제 결과와 실제 파일 상태" : "원본·이름 변경 파일의 내용과 탐지 이벤트"}</dd>
                        </div>
                      </dl>
                    </div>
                  </div>
                )}
                </div>
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
                  {cancellationPending
                    ? "테스트 프로세스의 종료를 확인하고 있습니다. " +
                      "HoldFS에 접수된 작업은 자체 정책에 따라 처리됩니다."
                    : "파일 작업 및 지연 반영을 확인하고 있습니다. " +
                      "완료된 단계부터 진행 상태가 갱신됩니다."}
                </p>
              )}

              <ol
                className="run-steps"
                style={{ "--step-count": Math.max(steps.length, 1) } as CSSProperties}
              >
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

              {(!selected.enabled || modeUnavailable) && (
                <p className="demo-notice">
                  {!selected.enabled
                    ? selected.disabled_reason ?? "실행 기능을 준비 중입니다."
                    : selectedModeDefinition?.disabled_reason ??
                      "선택한 모드의 실행 기능을 준비 중입니다."}
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
                  disabled={busy || loading || !selected.enabled || modeUnavailable}
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
                            : selected.id === "S03"
                              ? `${selectedMode === "read" ? "일반 읽기" : selectedMode === "honeypot" ? "허니팟 접근" : "로그 삭제"} 실행`
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

            </section>
          )}

          {/* 목록을 불러오지 못해도 실행 조회 복구는 가능해야 한다. */}
          {pollError && (
            <div className="demo-notice error" role="alert">
              <p>상태 조회 실패: {pollError}</p>
              <p>실제 테스트 실패를 의미하지 않습니다.</p>
              <button
                type="button"
                onClick={() => {
                  setPollRetry((value) => value + 1);
                  setListRetry((value) => value + 1);
                }}
              >
                같은 실행 다시 조회
              </button>
            </div>
          )}

          {/* 테스트 프로세스 종료와 HoldFS의 후속 처리는 구분한다. */}
          {runId && run && !isFinished(run.status) && (
            <div className="run-cancel">
              <div>
                <strong>
                  {cancellationPending
                    ? "테스트 프로세스를 종료하고 있습니다."
                    : "테스트 프로세스의 실행을 멈출 수 있습니다."}
                </strong>
                <p>
                  이미 접수된 작업은 HoldFS 정책에 따라
                  프로세스 종료 후에도 반영될 수 있습니다.
                </p>
              </div>

              <button
                type="button"
                onClick={() => void handleCancel()}
                disabled={cancellationPending}
              >
                {cancelSubmitting
                  ? "종료 요청 중"
                  : cancellationPending
                    ? "프로세스 종료 중"
                    : "테스트 프로세스 중단"}
              </button>
            </div>
          )}

          {cancelError && (
            <div className="demo-notice error" role="alert">
              {cancelError}
            </div>
          )}

          {/* 실행 ID를 받은 직후부터 진행 중·완료 후 모두 표시한다. */}
          {runId && (
            <RunInfo
              runId={runId}
              run={run}
              stale={Boolean(pollError)}
            />
          )}

          {/* 파일 작업 성공을 탐지·오탐 검증 성공과 구분한다. */}
          {run && isFinished(run.status) && (
            <RunResult run={run} />
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
