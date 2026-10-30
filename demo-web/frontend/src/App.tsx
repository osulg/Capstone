import { useCallback, useEffect, useRef, useState } from "react";

import Demo from "./screen/Demo";
import Intro from "./screen/Intro";

export default function App() {
  const [screen, setScreen] = useState<"intro" | "demo">("intro");

  // 처음에는 데모를 생성하지 않는다.
  // 처음 방문한 이후에는 유지해서 실행 결과를 보존한다.
  const [demoVisited, setDemoVisited] = useState(false);
  const demoContainerRef = useRef<HTMLDivElement>(null);

  const openDemo = useCallback(() => {
    setDemoVisited(true);
    setScreen("demo");
  }, []);

  const replayIntro = useCallback(() => {
    setScreen("intro");
  }, []);

  useEffect(() => {
    if (screen === "demo") {
      demoContainerRef.current?.focus();
    }
  }, [screen]);

  return (
    <>
      {screen === "intro" && <Intro onComplete={openDemo} />}

      {demoVisited && (
        <div
          ref={demoContainerRef}
          hidden={screen !== "demo"}
          tabIndex={-1}
          className="demo-screen-container"
        >
          <Demo onReplayIntro={replayIntro} />
        </div>
      )}
    </>
  );
}
