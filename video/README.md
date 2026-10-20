# AEOS Guard — explainer video

A 60-second Remotion explainer for the project: what the three defence
layers are, and the three ways an agent can be attacked.

| | |
| --- | --- |
| Format | 1920×1080, 30 fps, 1800 frames (60 s) |
| Fonts | Calibri (display), Consolas (mono) |
| Palette | black canvas · tool guard `#5b9dff` · memory guard `#2dd4bf` · reasoning guard `#a78bfa` · alert `#f4564a` · safe `#35d07f` |

## Layout

- `SCRIPT.md` — the script. Narration, per-scene timings, and the on-screen
  copy. **Read this first**: the code renders what the script says.
- `src/Root.tsx` — the composition, its duration and its frame rate.
- `src/scenes-a.tsx`, `src/scenes-b.tsx` — the scene components, in order.
- `src/lib.tsx` — the shared primitives: the slab, the wires, the evidence
  cards, and the palette constants.
- `src/Explainer.tsx` — the entry component.
- `src/index.ts` — the Remotion entry point.

## Commands

```bash
npm ci
npm start        # Remotion studio, for previewing
npm run render   # -> out/aeos-guard.mp4
npm run still    # -> out/frame.png, a single frame for thumbnails
```

The render needs a Chromium, which Remotion downloads on first use.

## The rendered file

`out/aeos-guard.mp4` is committed. It is a build artifact and would normally
be ignored, but it was the only copy of the rendered video, so it was
preserved rather than regenerated. The source reproduces it; the mp4 does
not reproduce the source.
