import React from "react";
import {
  AbsoluteFill,
  Easing,
  interpolate,
  spring,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";

/* ── palette ─────────────────────────────────────────────────────────────
   Lifted from the dashboard theme so the film and the product agree. */
export const C = {
  bg: "#000000",
  ink: "#f2f3f6",
  dim: "#9aa1ad",
  faint: "#6b7280",
  line: "rgba(255,255,255,0.10)",
  lineSoft: "rgba(255,255,255,0.055)",
  card: "rgba(255,255,255,0.045)",
  card2: "rgba(255,255,255,0.075)",
  tool: "#5b9dff",
  memory: "#2dd4bf",
  reason: "#a78bfa",
  alert: "#f4564a",
  warn: "#f6b73c",
  ok: "#35d07f",
};

export const F = {
  display: 'Calibri, "Segoe UI", system-ui, sans-serif',
  mono: 'Consolas, "Cascadia Mono", ui-monospace, monospace',
};

/* ── motion helpers ───────────────────────────────────────────────────── */

/** 0→1 spring, `delay` frames after this component's sequence started. */
export const useRise = (delay = 0, damping = 200, mass = 0.7) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  return spring({ frame: frame - delay, fps, config: { damping, mass } });
};

/** Linear 0→1 over [delay, delay+dur], eased. */
export const useRamp = (delay: number, dur: number) => {
  const frame = useCurrentFrame();
  return interpolate(frame, [delay, delay + dur], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.bezier(0.22, 1, 0.36, 1),
  });
};

/** Enter-from-below style for any block. */
export const rise = (p: number, dist = 26) => ({
  opacity: p,
  transform: `translateY(${(1 - p) * dist}px)`,
});

/* ── chrome ───────────────────────────────────────────────────────────── */

/** Faint engineering grid + vignette. Static-feeling, very low contrast. */
export const Backdrop: React.FC<{ hue?: string }> = ({ hue = C.ink }) => {
  const frame = useCurrentFrame();
  const drift = (frame * 0.12) % 60;
  return (
    <AbsoluteFill style={{ backgroundColor: C.bg }}>
      <AbsoluteFill
        style={{
          backgroundImage: `linear-gradient(${C.lineSoft} 1px, transparent 1px),
            linear-gradient(90deg, ${C.lineSoft} 1px, transparent 1px)`,
          backgroundSize: "60px 60px",
          backgroundPosition: `${-drift}px ${-drift}px`,
          opacity: 0.5,
        }}
      />
      <AbsoluteFill
        style={{
          background: `radial-gradient(120% 90% at 50% 0%, ${hue}14 0%, transparent 55%)`,
        }}
      />
      <AbsoluteFill
        style={{
          background:
            "radial-gradient(110% 80% at 50% 50%, transparent 40%, rgba(0,0,0,0.85) 100%)",
        }}
      />
    </AbsoluteFill>
  );
};

/** Per-scene fade so cuts breathe instead of snapping. */
export const Scene: React.FC<{
  dur: number;
  hue?: string;
  children: React.ReactNode;
}> = ({ dur, hue, children }) => {
  const frame = useCurrentFrame();
  const opacity = interpolate(
    frame,
    [0, 8, dur - 10, dur],
    [0, 1, 1, 0],
    { extrapolateLeft: "clamp", extrapolateRight: "clamp" },
  );
  return (
    <AbsoluteFill style={{ opacity }}>
      <Backdrop hue={hue} />
      {children}
    </AbsoluteFill>
  );
};

/** Small all-caps kicker with wide tracking. */
export const Kicker: React.FC<{
  children: React.ReactNode;
  color?: string;
  style?: React.CSSProperties;
}> = ({ children, color = C.faint, style }) => (
  <div
    style={{
      fontFamily: F.mono,
      fontSize: 17,
      letterSpacing: 4,
      textTransform: "uppercase",
      color,
      ...style,
    }}
  >
    {children}
  </div>
);

/** Scene header: index + guard name on one rule, headline underneath. */
export const Header: React.FC<{
  index: string;
  label: string;
  title: string;
  color?: string;
  delay?: number;
}> = ({ index, label, title, color = C.ink, delay = 0 }) => {
  const a = useRise(delay);
  const b = useRise(delay + 5);
  const w = useRamp(delay, 26);
  return (
    <div style={{ position: "absolute", left: 108, top: 92, right: 108 }}>
      <div
        style={{
          display: "flex",
          alignItems: "baseline",
          gap: 20,
          ...rise(a, 14),
        }}
      >
        <Kicker color={color}>{index}</Kicker>
        <Kicker>{label}</Kicker>
      </div>
      <div
        style={{
          height: 1,
          marginTop: 18,
          background: color,
          opacity: 0.35,
          transformOrigin: "left",
          transform: `scaleX(${w})`,
        }}
      />
      <div
        style={{
          fontFamily: F.display,
          fontSize: 62,
          fontWeight: 700,
          letterSpacing: -1.2,
          color: C.ink,
          marginTop: 22,
          ...rise(b, 20),
        }}
      >
        {title}
      </div>
    </div>
  );
};

/** Translucent surface with a hairline border. */
export const Panel: React.FC<{
  children?: React.ReactNode;
  style?: React.CSSProperties;
  accent?: string;
  glow?: number;
}> = ({ children, style, accent, glow = 0 }) => (
  <div
    style={{
      background: C.card,
      border: `1px solid ${accent ? `${accent}55` : C.line}`,
      borderRadius: 16,
      boxShadow: glow
        ? `0 0 ${28 * glow}px ${(accent ?? C.ink)}${Math.round(glow * 60)
            .toString(16)
            .padStart(2, "0")}`
        : "0 8px 30px rgba(0,0,0,0.5)",
      ...style,
    }}
  >
    {children}
  </div>
);

/** Rounded status chip. */
export const Chip: React.FC<{
  children: React.ReactNode;
  color?: string;
  filled?: boolean;
  style?: React.CSSProperties;
}> = ({ children, color = C.dim, filled, style }) => (
  <span
    style={{
      fontFamily: F.mono,
      fontSize: 15,
      letterSpacing: 1.6,
      textTransform: "uppercase",
      color: filled ? "#0a0b0d" : color,
      background: filled ? color : `${color}1a`,
      border: `1px solid ${color}${filled ? "" : "55"}`,
      borderRadius: 999,
      padding: "6px 14px",
      whiteSpace: "nowrap",
      ...style,
    }}
  >
    {children}
  </span>
);

/** The monolith: a slab with three layer bars lighting inside it. */
export const Slab: React.FC<{
  p: number;
  bars: number[];
  w?: number;
  h?: number;
}> = ({ p, bars, w = 168, h = 400 }) => {
  const colors = [C.tool, C.memory, C.reason];
  return (
    <div
      style={{
        width: w,
        height: h,
        borderRadius: 10,
        border: `1px solid rgba(255,255,255,${0.1 + 0.25 * p})`,
        background:
          "linear-gradient(180deg, rgba(255,255,255,0.075) 0%, rgba(255,255,255,0.02) 100%)",
        boxShadow: `0 0 ${70 * p}px rgba(255,255,255,${0.12 * p})`,
        transformOrigin: "bottom center",
        transform: `scaleY(${p})`,
        display: "flex",
        flexDirection: "column",
        justifyContent: "center",
        gap: 26,
        padding: "0 26px",
        overflow: "hidden",
      }}
    >
      {colors.map((c, i) => (
        <div
          key={c}
          style={{
            height: 6,
            borderRadius: 3,
            background: c,
            opacity: bars[i],
            transformOrigin: "left",
            transform: `scaleX(${bars[i]})`,
            boxShadow: `0 0 20px ${c}`,
          }}
        />
      ))}
    </div>
  );
};

/** A dot travelling a straight run, used for every flow line. */
export const Packet: React.FC<{
  x1: number;
  y1: number;
  x2: number;
  y2: number;
  t: number;
  color: string;
  size?: number;
}> = ({ x1, y1, x2, y2, t, color, size = 9 }) => {
  if (t <= 0 || t >= 1) return null;
  const x = x1 + (x2 - x1) * t;
  const y = y1 + (y2 - y1) * t;
  return (
    <div
      style={{
        position: "absolute",
        left: x - size / 2,
        top: y - size / 2,
        width: size,
        height: size,
        borderRadius: "50%",
        background: color,
        boxShadow: `0 0 16px ${color}, 0 0 34px ${color}80`,
      }}
    />
  );
};

/** Straight connector that draws itself in. */
export const Wire: React.FC<{
  x1: number;
  y1: number;
  x2: number;
  y2: number;
  p: number;
  color?: string;
  width?: number;
}> = ({ x1, y1, x2, y2, p, color = C.line, width = 1 }) => {
  const len = Math.hypot(x2 - x1, y2 - y1);
  const ang = (Math.atan2(y2 - y1, x2 - x1) * 180) / Math.PI;
  return (
    <div
      style={{
        position: "absolute",
        left: x1,
        top: y1 - width / 2,
        width: len,
        height: width,
        background: color,
        transformOrigin: "left center",
        transform: `rotate(${ang}deg) scaleX(${p})`,
      }}
    />
  );
};

/** Word-by-word reveal for narration-weight lines. */
export const Words: React.FC<{
  text: string;
  delay: number;
  step?: number;
  style?: React.CSSProperties;
}> = ({ text, delay, step = 2.5, style }) => {
  const frame = useCurrentFrame();
  return (
    <span style={style}>
      {text.split(" ").map((word, i) => {
        const o = interpolate(frame, [delay + i * step, delay + i * step + 9], [0, 1], {
          extrapolateLeft: "clamp",
          extrapolateRight: "clamp",
        });
        return (
          <span
            key={`${word}-${i}`}
            style={{
              display: "inline-block",
              opacity: o,
              transform: `translateY(${(1 - o) * 12}px)`,
            }}
          >
            {word}
            {" "}
          </span>
        );
      })}
    </span>
  );
};

/** Footer strap used to close most scenes. */
export const Strap: React.FC<{ text: string; delay: number; color?: string }> = ({
  text,
  delay,
  color = C.dim,
}) => {
  const p = useRise(delay);
  return (
    <div
      style={{
        position: "absolute",
        left: 108,
        bottom: 74,
        fontFamily: F.display,
        fontSize: 30,
        color,
        ...rise(p, 16),
      }}
    >
      {text}
    </div>
  );
};
