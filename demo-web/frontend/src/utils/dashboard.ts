// HoldFS 대시보드 주소. run_demo_web.sh가 대시보드를 127.0.0.1:5000에 띄운다.
// 다른 주소를 쓸 때는 빌드·개발 서버 실행 시 VITE_DASHBOARD_URL로 지정한다.
const DEFAULT_DASHBOARD_URL = "http://127.0.0.1:5000";

export const DASHBOARD_URL: string = (
  import.meta.env.VITE_DASHBOARD_URL || DEFAULT_DASHBOARD_URL
).replace(/\/+$/, "");

/** 대시보드 주소. PID를 주면 해당 PID 상세 화면으로 바로 연다. */
export function dashboardUrl(pid?: number | null): string {
  if (pid == null || !Number.isSafeInteger(pid) || pid <= 0) {
    return `${DASHBOARD_URL}/`;
  }

  const params = new URLSearchParams({ view: "events", pid: String(pid) });
  return `${DASHBOARD_URL}/?${params.toString()}`;
}
