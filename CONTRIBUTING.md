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
| Unified dashboard | [`dashboard/`](dashboard/) | Next.js 16 / React 19.2 |

## Development setup

```sh
# Shared contracts
py -3.12 contracts/check_contracts.py

# MCP-Shield
cd mcp-shield
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
bash fixtures/run_demo.sh

# VectorAnchor
cd vector-anchor
python -m pip install --require-hashes -r requirements.lock -r ../requirements-quality.lock
python -m pytest tests/

# TraceAudit
cd trace-audit
python -m pip install --require-hashes -r requirements.lock -r ../requirements-quality.lock
python -m pytest tests/

# Dashboard
cd dashboard && npm ci && npm test && npm run lint && npm run build

# Full stack (requires Docker)
docker compose up -d --build && ./run_full_demo.sh

# Full demo without Docker (requires a local PostgreSQL 17 server + psql)
DASH_PORT=3101 bash scripts/run_local_demo.sh
```

## Ground rules

- **Run the tests** for any module you touch, and add tests for new behavior.
  The unit tests for the Python detectors (`vector-anchor`, `trace-audit`)
  are dependency-light and run with just `pytest`.
- **Keep the shared contracts.** Update `contracts/schemas/`, OpenAPI, canonical
  fixtures, and compatibility tests together. Do not silently diverge from the
  versioned event envelope.
- **Do not rewrite applied migrations.** Migration checksums deliberately fail
  when historical SQL changes. Add a new ordered migration instead.
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
