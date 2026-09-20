#!/usr/bin/env sh
set -eu
command -v python3 >/dev/null || { echo 'Python 3.12 is required' >&2; exit 1; }
command -v node >/dev/null || { echo 'Node 22 is required' >&2; exit 1; }
command -v npm >/dev/null || { echo 'npm is required' >&2; exit 1; }
command -v psql >/dev/null || { echo 'PostgreSQL client tools are required' >&2; exit 1; }
[ -d .venv ] || python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r vector-anchor/requirements.lock -r trace-audit/requirements.lock
npm ci --prefix dashboard
npm run build --prefix dashboard
[ -f .env ] || .venv/bin/python scripts/generate_secrets.py
printf '%s\n' 'Installed. Configure DATABASE_ADMIN_URL and DATABASE_URL in .env, then run:'
printf '%s\n' '.venv/bin/python scripts/run_local_demo.py --skip-build'
