# GitHub triage pilot verification

The release remains a pilot candidate. Local verification uses PostgreSQL 17 and
a GitHub API stub. A dedicated GitHub test repository and green hosted CI are
required for the pilot-ready designation.

| Gate | Local result |
| --- | --- |
| Clean Linux onboarding at `c5bb2e7` | `init` created a gitignored mode-600 `.env` and preserved it on retry. `doctor` passed all five checks. The offline gateway demo passed six assertions and recorded four events across MCP-Shield, VectorAnchor, and TraceAudit. |
| Authenticated workload | Live PostgreSQL-backed checks rejected missing credentials and forged tenant headers on retrieval and all three generation endpoints. The authenticated launcher recorded events under the granted identity. Revocation blocked new retrieval and generation immediately in the check. A different agent with the same session ID remained usable. Restoring the original session readmitted it. |
| GitHub approval workflow | PostgreSQL-backed integration verified exact reply bytes, label addition and removal, replay and concurrent approval, tenant isolation, and queue revocation. Denied, expired, changed, and revoked actions made zero write requests. An ambiguous response was recorded as `uncertain`, and a retry made no write. |
| Database row isolation | A direct query as `monolith_app`, without an explicit tenant predicate, saw zero approval rows for an unrelated tenant and two for the fixture tenant. |
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

Local suites reported 66 script tests, 57 shared Python tests, 165 VectorAnchor
tests, 261 TraceAudit tests and one expected failure, 164 dashboard tests, and
two GitHub triage tests. Ruff, dashboard lint, TypeScript, the Next.js build,
the contract checker, and `docker compose config --quiet` passed. The full
container run remains unverified because the executor ran out of disk space
extracting its Docker images.

## Versioned native release

The Linux `0.4.0-rc.3` archive was built from `6d9764b`. Its SHA-256 is
`0a53dad3be76f98b12f0900eb8fe692803a2ee6266fd6aeaf0546499f4f75360`.
The comparison release was `0.3.0-rc.1` from `c5bb2e7`. The first restart
attempt exposed a Linux port preflight failure while old connections were in
`TIME_WAIT`. Commit `6d9764b` corrected the check and added a regression test.

```sh
python3 scripts/package_release.py --revision c5bb2e7 --version 0.3.0-rc.1 --output /workspace/work/monolith-pilot-releases
python3 scripts/build_platform_bundle.py --revision 6d9764b --platform linux-x86_64 --version 0.4.0-rc.3 --output /workspace/work/monolith-pilot-releases
(cd /workspace/work/monolith-pilot-releases && sha256sum -c black-monolith-0.3.0-rc.1-source.zip.sha256 black-monolith-0.4.0-rc.3-linux-x86_64.zip.sha256)
/workspace/work/monolith-services/bin/python /workspace/work/monolith-release-check.py
```

The release check builds and runs the extracted code against disposable native
PostgreSQL databases. The local harness and stub are under `/workspace/work`.
The clean install and same-port restart preserved proposal history and rejected
approval replay. The PostgreSQL backup restored into a new database, retained
the succeeded approval, and expired the stale pending proposal before re-enabling
the provider stub. The previous release upgraded to the pilot, rolled back on
the same database, then rolled forward with the approved action intact and its
replay rejected. Container volume restore remains unverified.
