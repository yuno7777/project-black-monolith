# GitHub triage pilot verification

The release remains a pilot candidate. Local verification uses PostgreSQL 17 and
a GitHub API stub. A dedicated GitHub test repository and green hosted CI are
required for the pilot-ready designation.

| Gate | Local result |
| --- | --- |
| Clean Linux onboarding at `c5bb2e7` | `init` created a gitignored mode-600 `.env` and preserved it on retry. `doctor` passed all five checks. The offline gateway demo passed six assertions and recorded four events across MCP-Shield, VectorAnchor, and TraceAudit. |
| Authenticated workload | Live PostgreSQL-backed checks rejected missing credentials and forged tenant headers on retrieval and all three generation endpoints. The authenticated launcher recorded events under the granted identity. Revocation blocked new retrieval and generation immediately in the check. A different agent with the same session ID remained usable. Restoring the original session readmitted it. |
| GitHub approval workflow | PostgreSQL-backed integration verified exact reply bytes, label addition and removal, replay and concurrent approval, tenant isolation, and queue revocation. Denied, expired, changed, and revoked actions made zero write requests. An ambiguous response was recorded as `uncertain`, and a retry made no write. |
| Live GitHub integration | Pending. The connected GitHub credential could not create a dedicated repository, and the operator requested local verification while a test repository is unavailable. |

## Reproduce the local suites

Run the commands below with the locked dependencies installed. The triage
integration needs a disposable, migrated PostgreSQL database and both its admin
and restricted runtime connection strings.

```sh
python3 -m unittest discover -s scripts/tests
(cd python-common && python3 -m pytest -q tests)
(cd vector-anchor && python3 -m pytest -q tests)
(cd trace-audit && python3 -m pytest -q tests)
python3 contracts/check_contracts.py
npm --prefix dashboard test
npm --prefix dashboard run lint
npm --prefix dashboard run build

DATABASE_MIGRATIONS_DIR="$PWD/supabase/migrations" \
  DATABASE_URL="$DATABASE_ADMIN_URL" node dashboard/scripts/migrate.mjs
(cd dashboard && MONOLITH_TRIAGE_TEST_DATABASE_ADMIN_URL="$DATABASE_ADMIN_URL" \
  ./node_modules/.bin/tsx --test test/github-triage.test.ts)
```

The native CI smoke runner invokes the PostgreSQL-backed triage test in its
disposable database after the stack check. To run the offline gateway demo
against a running stack, run `./monolith doctor` and then
`python3 scripts/run_gateway_demo.py`.
