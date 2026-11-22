import type { View } from "./components/Tabs";

// 웹 시연 화면 등 외부에서 대시보드를 열 때 쓰는 주소 파라미터.
//   /?view=events&pid=1234  → 보안 이벤트 현황에서 PID 1234 상세를 바로 연다
//   /?view=files            → 파일 현황 메뉴로 연다
//   /?run=s04_…             → 파일 현황 › 실행별 상세에서 그 실행 폴더를 연다
// 알 수 없는 값은 무시하고 기본 화면을 보여준다.
export interface DeepLink {
  view: View;
  pid: number | null;
  run: string | null;   // ?run=s04_… → 파일 현황 › 실행별 상세
}

const VIEWS: readonly View[] = ["events", "files", "system", "ai"];

export function readDeepLink(search: string = window.location.search): DeepLink {
  const params = new URLSearchParams(search);

  const rawPid = params.get("pid");
  const pid = rawPid !== null && /^[1-9]\d{0,9}$/.test(rawPid) ? Number(rawPid) : null;

  const rawView = params.get("view");
  let view: View = VIEWS.includes(rawView as View) ? (rawView as View) : "events";
  const rawRun = params.get("run");
  const run = rawRun !== null && /^s0[1-4]_[0-9a-f]{32}$/.test(rawRun) ? rawRun : null;

  // PID 상세는 보안 이벤트 현황 안에, 실행별 상세는 파일 현황 안에 있다.
  if (pid !== null) view = "events";
  else if (run !== null) view = "files";

  return { view, pid, run };
}
