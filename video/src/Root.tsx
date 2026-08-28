import React from "react";
import { Composition } from "remotion";
import { Explainer, SCENES, TOTAL } from "./Explainer";

export const Root: React.FC = () => (
  <>
    <Composition
      id="Explainer"
      component={Explainer}
      durationInFrames={TOTAL}
      fps={30}
      width={1920}
      height={1080}
    />
    {/* Each scene on its own, so a single beat can be scrubbed in Studio. */}
    {SCENES.map((s) => (
      <Composition
        key={s.name}
        id={s.name}
        component={s.C}
        durationInFrames={s.dur}
        fps={30}
        width={1920}
        height={1080}
      />
    ))}
  </>
);
