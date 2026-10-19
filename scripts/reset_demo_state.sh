#!/usr/bin/env bash
# Compatibility wrapper; resets detector history, never PostgreSQL evidence.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then PY=python; fi
exec "$PY" "$ROOT/scripts/reset_demo_state.py" "$@"
