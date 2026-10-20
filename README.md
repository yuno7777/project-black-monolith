# AEOS Guard — the 60-second explainer

This branch carries one thing: the Remotion project that renders the
"AEOS Guard" explainer video, and the rendered `out/aeos-guard.mp4`.

It is a **standalone branch on purpose**. The work lived only on
`codex/preserve-local-work-2026-08-28`, a branch that was 31 commits behind
`main` and contained a snapshot of the whole codebase from that time. The
integration plan (`docs/INTEGRATION_PLAN.md` on `main`) called for that branch
to be deleted once its unique contents had been moved elsewhere — and it
warned, correctly, that "that branch is the only place that work exists".

This branch is that elsewhere. It contains the video project and nothing
else, so:

- the explainer can no longer be lost by a branch deletion or a worktree
  prune, and
- merging it into `main` adds the video project alone. It does **not**
  restore the old codebase, because the old codebase was never brought
  across.

## What is here

| Path | What it is |
| --- | --- |
| `video/SCRIPT.md` | The script: narration, timings, on-screen copy, per scene. This is the document to change first. |
| `video/src/` | The Remotion scenes. `scenes-a.tsx` and `scenes-b.tsx` hold the scene components; `lib.tsx` holds the shared primitives (the slab, the wires, the evidence cards, the palette). |
| `video/src/Root.tsx` | The composition and its duration. |
| `video/package.json` | The scripts: `start`, `render`, `still`. |
| `video/out/aeos-guard.mp4` | The rendered video. |

## Rendering

```bash
cd video
npm ci
npm run render      # -> out/aeos-guard.mp4
```

`npm start` opens the Remotion studio for previewing. The render needs a
Chromium, which Remotion downloads on first use; a machine without network
access cannot render it.

`out/aeos-guard.mp4` is committed deliberately. It is a build artifact, and
normally `out/` would be gitignored — but it was the only copy of the
rendered video, so it was preserved rather than regenerated. The source can
reproduce it; the reverse is not true of the mp4.

## Provenance

The project was written on the `codex/preserve-local-work-2026-08-28`
branch and moved here verbatim, as a single snapshot. The branch's own
history was not carried across: it consisted of one bulk commit
(`b958faf`, "chore: preserve local work before automation") on top of a
stale copy of the whole repository, and the files are byte-identical.

## If you merge this into `main`

Merge it as a normal branch. The result is `main` plus a `video/` directory
and nothing else. The explainer is a separate concern from the runtime, so
whether `main` should carry it, or whether it should live as its own
repository, is a call for the project owner.
