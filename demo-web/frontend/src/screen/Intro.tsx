import { useCallback, useEffect, useRef, useState } from "react";

interface IntroProps {
  onComplete: () => void;
}

// 시나리오가 확정되기 전이므로 특정 공격 사례에 종속되지 않는 문구.
const SLIDES = [
  {
    label: "일상적인 파일 작업",
    title: ["평범한 작업의 순간에도,", "원본 보호는 필요합니다."],
    description:
      "문서를 열고 수정하고 저장하는 일상적인 흐름 속에서, 정상 작업과 의심스러운 변경을 구분해야 합니다.",
  },
  {
    label: "HoldFS의 보호 방식",
    title: ["파일의 변경을 관찰하고,", "정책에 따라 보호합니다."],
    description:
      "HoldFS는 프로세스의 파일 작업을 관찰하고, 판단된 상태와 정책에 따라 변경을 반영하거나 지연·차단합니다.",
  },
  {
    label: "직접 확인하는 실행 결과",
    title: ["이제, 테스트를 실행하고", "보호 동작을 확인하세요."],
    description:
      "격리된 테스트 환경의 전용 파일로 시연합니다. 실행 단계와 결과를 확인하고, 작업 PID로 대시보드 이벤트를 살펴보세요.",
  },
];

export default function Intro({ onComplete }: IntroProps) {
  const [index, setIndex] = useState(0);
  const headingRef = useRef<HTMLHeadingElement>(null);

  const slide = SLIDES[index];
  const isLast = index === SLIDES.length - 1;

  const next = useCallback(() => {
    if (index === SLIDES.length - 1) {
      onComplete();
      return;
    }

    setIndex((current) => current + 1);
  }, [index, onComplete]);

  // 장면 전환 후 제목으로 초점을 옮긴다.
  useEffect(() => {
    headingRef.current?.focus();
  }, [index]);

  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      if (
        event.key !== "Enter" ||
        event.repeat ||
        event.isComposing ||
        event.ctrlKey ||
        event.altKey ||
        event.metaKey ||
        event.shiftKey
      ) {
        return;
      }

      // 버튼에서 Enter를 누른 경우 브라우저의 기본 클릭만 사용한다.
      // 전역 키 처리와 중복되어 두 장면을 넘기는 것을 방지한다.
      const target = event.target;

      if (
        target instanceof Element &&
        target.closest("button, a, input, textarea, select, [contenteditable]")
      ) {
        return;
      }

      event.preventDefault();
      next();
    }

    window.addEventListener("keydown", handleKeyDown);

    return () => {
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [next]);

  return (
    <main className="intro-page">
      <header className="intro-header">
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

        <span className="intro-header-label">DEMO</span>
      </header>

      <section className="intro-content" aria-labelledby="intro-title">
        <div className="intro-slide" key={index}>
          <p className="intro-counter">
            {String(index + 1).padStart(2, "0")} /{" "}
            {String(SLIDES.length).padStart(2, "0")}
          </p>

          <p className="intro-label">{slide.label}</p>

          <h1 id="intro-title" ref={headingRef} tabIndex={-1}>
            {slide.title.map((line) => (
              <span key={line}>{line}</span>
            ))}
          </h1>

          <p className="intro-description">{slide.description}</p>

          <button
            type="button"
            className="intro-next-button"
            onClick={next}
          >
            <span>{isLast ? "데모 시작하기" : "계속하기"}</span>
            <span aria-hidden="true">→</span>
          </button>
        </div>
      </section>

      <footer className="intro-footer">
        <nav className="intro-indicators" aria-label="인트로 장면">
          {SLIDES.map((item, slideIndex) => (
            <button
              key={item.label}
              type="button"
              className={slideIndex === index ? "is-active" : ""}
              aria-label={`${slideIndex + 1}번째 장면: ${item.label}`}
              aria-current={slideIndex === index ? "step" : undefined}
              onClick={() => setIndex(slideIndex)}
            />
          ))}
        </nav>

        <p className="intro-key-hint">
          <kbd>Enter</kbd>
          <span>{isLast ? "데모 화면으로" : "다음 장면"}</span>
        </p>
      </footer>
    </main>
  );
}
