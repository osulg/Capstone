import type { Run } from "../types/api";
import { dashboardUrl } from "../utils/dashboard";
import { getRunPresentation } from "../utils/runPresentation";

interface RunInfoProps {
  runId: string;
  run: Run | null;

  /** 조회 실패 시 현재 표시가 마지막으로 받은 정보임을 안내한다. */
  stale: boolean;
}

const ROLE_LABELS: Record<string, string> = {
  normal_worker: "정상 작업",
};

function roleLabel(role: string): string {
  // 새로운 역할이 추가되어도 원래 이름으로 표시할 수 있다.
  return ROLE_LABELS[role] ?? role;
}

export default function RunInfo({
  runId,
  run,
  stale,
}: RunInfoProps) {
  // 첫 조회 전에는 등록 정보를 아직 받지 못한 상태다.
  const processes = run?.processes ?? [];

  const finished =
    run !== null &&
    ["passed", "failed", "timed_out", "cancelled"].includes(run.status);

  return (
    <section
      className="run-info"
      aria-labelledby="run-info-heading"
    >
      <div className="run-info-heading">
        <h3 id="run-info-heading">실행 정보</h3>
        <span>
          {run ? getRunPresentation(run).label : "상태 확인 중"}
        </span>
      </div>

      {stale && (
        <p className="run-info-note">
          조회가 중단되어 마지막으로 받은 정보를 표시하고 있습니다.
        </p>
      )}

      <dl className="run-info-meta">
        <div>
          <dt>실행 ID</dt>
          <dd>
            <code>{runId}</code>
          </dd>
        </div>

        <div>
          <dt>관리자 PID</dt>
          <dd>{run?.pid ?? "확인되지 않음"}</dd>
        </div>

        <div>
          <dt>HoldFS PID</dt>
          <dd>{run?.holdfs_pid ?? "확인되지 않음"}</dd>
        </div>
      </dl>

      <h4>등록된 작업 프로세스</h4>

      {processes.length === 0 ? (
        <p className="run-info-note">
          {!run
            ? "실행 정보를 조회하고 있습니다."
            : finished
              ? "이 실행에 등록된 작업 프로세스가 없습니다."
              : "아직 등록된 작업 프로세스가 없습니다."}
        </p>
      ) : (
        <div className="run-info-table-wrap">
          <table className="run-info-table">
            <caption className="sr-only">
              이 실행에 등록된 작업 프로세스의 역할과 PID
            </caption>

            <thead>
              <tr>
                <th scope="col">역할</th>
                <th scope="col">작업 PID</th>
              </tr>
            </thead>

            <tbody>
              {processes.map((process) => (
                <tr
                  key={`${process.pid}:${process.start_time_ticks}`}
                >
                  <td>
                    <strong>{roleLabel(process.role)}</strong>
                    <code>{process.role}</code>
                  </td>

                  <td>
                    <a
                      className="dashboard-link"
                      href={dashboardUrl(process.pid)}
                      target="_blank"
                      rel="noopener noreferrer"
                      title={`대시보드에서 PID ${process.pid} 상세 보기 (새 탭)`}
                    >
                      {process.pid}
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="run-info-note">
        작업 PID를 누르면 대시보드에서 해당 PID의 파일 작업 이벤트를 확인할 수 있습니다.
        이 목록은 등록 이력이며 현재 프로세스의 생존 여부를 뜻하지 않습니다.{" "}
        <a
          className="dashboard-link"
          href={dashboardUrl()}
          target="_blank"
          rel="noopener noreferrer"
        >
          대시보드 열기 ↗
        </a>
      </p>
    </section>
  );
}
