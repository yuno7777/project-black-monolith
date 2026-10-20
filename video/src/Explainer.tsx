import React from "react";
import { AbsoluteFill, Sequence } from "remotion";
import { C } from "./lib";
import { Idea, Open, Surfaces, ToolGuard } from "./scenes-a";
import { MemoryGuard, ReasoningGuard, Record, Results } from "./scenes-b";

/** 0:00 → 1:00. Durations sum to 1800 frames at 30 fps. */
export const SCENES = [
  { name: "Open", dur: 150, C: Open },
  { name: "Surfaces", dur: 210, C: Surfaces },
  { name: "Idea", dur: 180, C: Idea },
  { name: "ToolGuard", dur: 270, C: ToolGuard },
  { name: "MemoryGuard", dur: 270, C: MemoryGuard },
  { name: "ReasoningGuard", dur: 270, C: ReasoningGuard },
  { name: "Record", dur: 240, C: Record },
  { name: "Results", dur: 210, C: Results },
] as const;

export const TOTAL = SCENES.reduce((n, s) => n + s.dur, 0);

export const Explainer: React.FC = () => {
  let at = 0;
  return (
    <AbsoluteFill style={{ backgroundColor: C.bg }}>
      {SCENES.map((s) => {
        const from = at;
        at += s.dur;
        return (
          <Sequence key={s.name} from={from} durationInFrames={s.dur} name={s.name}>
            <s.C />
          </Sequence>
        );
      })}
    </AbsoluteFill>
  );
};
