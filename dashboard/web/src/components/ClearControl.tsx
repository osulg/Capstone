import { hhmmss } from "../fileStats";

interface Props {
  clearedAt: number | null;
  onClear?: () => void;
  onReset?: () => void;
}

// 목록 아래 '화면 정리' / '모두 다시 보기'. 화면에서만 숨기고 서버 기록·로그 파일은 지우지 않는다.
export default function ClearControl({ clearedAt, onClear, onReset }: Props) {
  if (!onClear) return null;
  return (
    <span className="clear-control">
      {clearedAt === null ? (
        <button className="link-btn" onClick={onClear} title="지금까지의 기록을 화면에서만 숨깁니다 (기록은 지우지 않음)">
          화면 정리
        </button>
      ) : (
        <>
          <span>{hhmmss(new Date(clearedAt))} 이후만 표시</span>
          <button className="link-btn" onClick={onReset}>모두 다시 보기</button>
        </>
      )}
    </span>
  );
}
