#!/usr/bin/env bash
# The agent gateway, end to end, with no API key and no credits.
#
# Runs a stand-in agent under `monolith wrap`, pointed at a local stub of the
# Anthropic Messages API that leaks AWS's published example key. The agent
# must never see the key, and the ledger must show that the redaction
# happened.
#
# Needs the stack up (`docker compose up -d --build`) and the host's Python
# to have fastapi, uvicorn and httpx installed.

set -euo pipefail

cd "$(dirname "$0")/.."

python scripts/run_gateway_demo.py
