#!/usr/bin/env bash
# Generate a local .env with random secrets for the Docker stack.
#
#   bash scripts/generate_secrets.sh          # create .env (refuses to clobber)
#   bash scripts/generate_secrets.sh --force  # regenerate, discarding the old one
#
# The values are development credentials for a single-machine stack: the
# Postgres password and the three per-module ingest bearer tokens. .env is
# gitignored — never commit it, and regenerate before using this anywhere but
# a local machine.
#
# Regenerating invalidates the tokens the running containers hold, so
# `docker compose up -d` afterwards to re-inject them. Changing the Postgres
# password after the database volume has been initialized will NOT take
# effect (the password is baked in at first init) — drop the volume with
# `docker compose down -v` if you need it to.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ -f .env ] && [ "${1:-}" != "--force" ]; then
  echo "refusing to overwrite the existing .env — pass --force to regenerate" >&2
  exit 1
fi

# 24 bytes of CSPRNG output as hex: 48 characters, URL-safe (the Postgres
# password is embedded in DATABASE_URL) and comfortably over the 16-character
# minimum the dashboard's ingest authenticator enforces.
gen() {
  openssl rand -hex 24 2>/dev/null || head -c 24 /dev/urandom | xxd -p | tr -d '\n'
}

cat > .env <<EOF
# Local development secrets — generated $(date +%Y-%m-%d). Gitignored; never commit.
# Regenerate any time with: bash scripts/generate_secrets.sh --force
MONOLITH_POSTGRES_PASSWORD=$(gen)
MONOLITH_EVENT_TOKEN_MCP_SHIELD=$(gen)
MONOLITH_EVENT_TOKEN_VECTOR_ANCHOR=$(gen)
MONOLITH_EVENT_TOKEN_TRACE_AUDIT=$(gen)
# The human operator's credential for the investigation queue. Separate from the
# module tokens above: those identify modules, and a module must not be able to
# close its own findings. The name is what the audit trail records.
MONOLITH_OPERATOR_NAME=operator
MONOLITH_OPERATOR_TOKEN=$(gen)
EOF

echo "wrote .env with 5 random secrets (values not printed)"
