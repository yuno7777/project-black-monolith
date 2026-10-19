#!/usr/bin/env bash
# Reset local demo state across Postgres, SQLite/JSONL outboxes, and detector state.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ -f "$ROOT/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/.env"
  set +a
fi

TRUNCATE_SQL="TRUNCATE monolith.security_events, monolith.incident_triage, monolith.incident_audit, monolith.alert_outbox CASCADE;"

if [[ -n "${DATABASE_URL:-}" ]] && command -v psql >/dev/null 2>&1; then
  psql "$DATABASE_URL" -c "$TRUNCATE_SQL" >/dev/null 2>&1 || true
elif command -v docker >/dev/null 2>&1; then
  docker compose -f "$ROOT/docker-compose.yml" exec -T database \
    psql -U postgres -d postgres -c "$TRUNCATE_SQL" >/dev/null 2>&1 || true
fi

rm -f \
  "$ROOT"/vector-anchor/outbox.db \
  "$ROOT"/vector-anchor/outbox.db-wal \
  "$ROOT"/vector-anchor/outbox.db-shm \
  "$ROOT"/trace-audit/outbox.db \
  "$ROOT"/trace-audit/outbox.db-wal \
  "$ROOT"/trace-audit/outbox.db-shm \
  "$ROOT"/mcp-shield/outbox.jsonl \
  "$ROOT"/vector-anchor/detector_state.json

PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then PY=python; fi
if [[ $# -gt 0 ]] || [[ -n "${MONOLITH_ADMIN_TOKEN:-}" ]]; then
  "$PY" "$ROOT/scripts/reset_demo_state.py" "$@" || true
fi
