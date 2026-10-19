#!/usr/bin/env bash
# Compatibility entry point; the implementation is native Python on every OS.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then PY=python; fi
exec "$PY" "$ROOT/scripts/generate_secrets.py" "$@"
