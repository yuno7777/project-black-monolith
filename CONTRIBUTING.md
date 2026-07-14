# Contributing to Project Black Monolith

Thanks for your interest in contributing. Project Black Monolith is a
**defensive** agent-security research project (Sleepers Research); all
"attack" material in the repo is local, self-contained detection-test
fixtures used only to validate the detectors. Please keep contributions in
that defensive spirit — see [SECURITY.md](SECURITY.md).

## Project layout

Each module is standalone, with its own README, tests, and demo:

| Module | Path | Stack |
| ------ | ---- | ----- |
| MCP-Shield (tool layer) | [`mcp-shield/`](mcp-shield/) | Rust / tokio |
| VectorAnchor (memory layer) | [`vector-anchor/`](vector-anchor/) | Python / FastAPI + ChromaDB |
| TraceAudit (reasoning layer) | [`trace-audit/`](trace-audit/) | Python / FastAPI |
| Unified dashboard | [`dashboard/`](dashboard/) | Next.js 15 |

## Development setup

```sh
# MCP-Shield
cd mcp-shield && cargo build && cargo test && bash fixtures/run_demo.sh

# VectorAnchor
cd vector-anchor && pip install -r requirements.txt && python -m pytest tests/

# TraceAudit
cd trace-audit && pip install -r requirements.txt && python -m pytest tests/

# Dashboard
cd dashboard && npm install && npm run build

# Full stack
docker compose up -d --build && ./run_full_demo.sh
```

## Ground rules

- **Run the tests** for any module you touch, and add tests for new behavior.
  The unit tests for the Python detectors (`vector-anchor`, `trace-audit`)
  are dependency-light and run with just `pytest`.
- **Keep the shared event shape.** All modules emit
  `{ timestamp_ms, module, event_type, severity, details }`. Don't diverge —
  the dashboard depends on it.
- **No secrets or absolute local paths** in tracked files. Configuration is
  via environment variables (see each module's README).
- **Keep dependencies minimal** — don't introduce a new framework beyond the
  existing stack (Rust/tokio, FastAPI, Next.js, ChromaDB, Ollama).

## Commit & PR conventions

- Use short, imperative summary lines, optionally with a
  [Conventional Commits](https://www.conventionalcommits.org/) prefix
  (`feat(mcp-shield): …`, `fix(dashboard): …`, `docs: …`, `ci: …`).
- Keep commits focused; add a body when the "why" isn't obvious.
- Open a PR against `main` using the pull-request template; describe what you
  changed, how you tested it, and link any related issue. CI must pass.

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE).
