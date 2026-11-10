import { hhmmss } from "../fileStats";

interface Props {
  clearedAt: number | null;
  onClear?: () => void;
  onReset?: () => void;
}

// 목록 아래 '로그 정리' / '로그 복원'. 화면에서만 숨기고 서버 기록·로그 파일은 지우지 않는다.
export default function ClearControl({ clearedAt, onClear, onReset }: Props) {
  if (!onClear) return null;
  return (
    <span className="clear-control">
      {clearedAt === null ? (
        <button className="btn" onClick={onClear} title="지금까지의 기록을 화면에서만 숨깁니다 (기록은 지우지 않음)">
          로그 정리
        </button>
      ) : (
        <>
          <span>{hhmmss(new Date(clearedAt))} 이후만 표시</span>
          <button className="btn" onClick={onReset} title="정리로 숨긴 기록을 다시 보여줍니다">로그 복원</button>
        </>
      )}
    </span>
  );
}
