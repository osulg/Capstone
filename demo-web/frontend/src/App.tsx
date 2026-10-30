import { useCallback, useEffect, useRef, useState } from "react";

import Demo from "./screen/Demo";
import Intro from "./screen/Intro";
import { readSavedRun } from "./utils/runSession";

export default function App() {
  const [savedRun] = useState(readSavedRun);

  const [screen, setScreen] = useState<"intro" | "demo">(
    savedRun ? "demo" : "intro",
  );

  const [demoVisited, setDemoVisited] = useState(
    savedRun !== null,
  );

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
      {screen === "intro" && (
        <Intro onComplete={openDemo} />
      )}

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
