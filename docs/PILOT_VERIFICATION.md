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
native smoke runner verified all three layers in PostgreSQL, ran the triage
integration tests, and confirmed service cleanup. The full container run
remains unverified because the executor ran out of disk space extracting its
Docker images.

## Versioned native release

The Linux `0.4.0-rc.4` archive was built from `ba1b28c`. Its SHA-256 is
`9b32e162cbb158c234e7b47cb87f68f37a744083a4b248af4455eb56a1cccbeb`.
The comparison release was `0.3.0-rc.1` from `c5bb2e7`. The first restart
attempt exposed a Linux port preflight failure while old connections were in
`TIME_WAIT`. Commit `6d9764b` corrected the check and added a regression test.
The broader native smoke found a stale MCP-Shield log assertion. Commit
`ba1b28c` switched the runner to the existing structured ledger assertion
and removed the GitHub credential from the other native service environments.

```sh
python3 scripts/package_release.py --revision c5bb2e7 --version 0.3.0-rc.1 --output /workspace/work/monolith-pilot-releases
python3 scripts/build_platform_bundle.py --revision ba1b28c --platform linux-x86_64 --version 0.4.0-rc.4 --output /workspace/work/monolith-pilot-releases
(cd /workspace/work/monolith-pilot-releases && sha256sum -c black-monolith-0.3.0-rc.1-source.zip.sha256 black-monolith-0.4.0-rc.4-linux-x86_64.zip.sha256)
/workspace/work/monolith-services/bin/python /workspace/work/monolith-release-check-rc4.py
```

The release check builds and runs the extracted code against disposable native
PostgreSQL databases. The local harness and stub are under `/workspace/work`.
The clean install and same-port restart preserved proposal history and rejected
approval replay. The PostgreSQL backup restored into a new database, retained
the succeeded approval, and expired the stale pending proposal before re-enabling
the provider stub. The previous release upgraded to the pilot, rolled back on
the same database, then rolled forward with the approved action intact and its
replay rejected.

## Docker module volume round-trip

The following procedure passed locally with disposable Docker volumes seeded
from a completed native smoke run. It used the Chroma store, detector state,
SQLite outboxes, and saved baselines produced by the actual modules.

```sh
bash scripts/pilot_module_volumes.sh backup "$FIXTURE_PROJECT" "$BACKUP_DIRECTORY"
bash scripts/pilot_module_volumes.sh restore "$RESTORE_PROJECT" "$BACKUP_DIRECTORY"
bash scripts/pilot_module_volumes.sh backup "$RESTORE_PROJECT" "$RECHECK_DIRECTORY"
```

All four restored archives preserved file contents, file timestamps, modes,
and numeric ownership. Directory timestamps changed on extraction. The
restored Chroma database was readable by the service's UID 10001. Backup
refused an attached running container, and restore refused a corrupted archive
and existing destination volumes. Hosted CI now includes the round-trip on
volumes populated by the Compose integration run. The complete Compose stack
still awaits that run on a host with sufficient storage.

## Live acceptance runner rehearsal

The three [acceptance commands](GITHUB_TRIAGE_QUICKSTART.md#record-live-acceptance-evidence)
were rehearsed against the real dashboard and a disposable PostgreSQL database
with a local HTTP fixture serving the GitHub API. Preparation queued all six
proposals without a write and rejected the changed payload with HTTP 409.
Three positive approvals produced one exact reply and two label updates. Replay,
denial, revocation, and expiry produced no additional writes. The verifier also
failed before expiration and detected a duplicate comment injected into the
fixture. The dedicated live repository remains required for final verification.

A headless Chromium rehearsal used the production dashboard build and the same
local GitHub HTTP fixture. A signed-in analyst approved the three intended
actions, denied one draft, and revoked the test session. Two label drafts had
identical payloads. Selecting the printed Action ID changed only the intended
record. The dashboard displayed the reviewer and GitHub comment ID, and the
viewer account could read the results without approval, denial, or revocation
controls. The three acceptance commands confirmed the resulting audit and
fixture state.

The same dashboard and PostgreSQL rehearsal exercised `--evidence` for both
check phases. Successful checks wrote JSON with the action IDs, digests, and
audit outcomes. The early expiry check and a duplicate-comment check produced
no files. The reports contained neither credentials nor reply text, and the
unit tests verified that an existing report cannot be overwritten.

The native CI smoke runner now runs this rehearsal from the checkout. From a
clean checkout with no `.env`, install the locked Python dependencies, build
the dashboard and the debug MCP-Shield binary, then run the following commands.
The runner creates and cleans up its own PostgreSQL database and GitHub fixture.

```sh
npm ci --prefix dashboard
npm --prefix dashboard run build
cargo build --locked --manifest-path mcp-shield/Cargo.toml
PG_BIN=/path/to/postgresql/17/bin python3 scripts/native_smoke.py
```

### Retry after a partial Docker volume restore

The integration workflow's module backup step now tests an extraction failure.
The following calls passed locally on Linux with Docker's VFS driver. The
source directory held the four archives from the module volume rehearsal.
The invalid directory contained copies with the third archive replaced by
plain text and SHA256SUMS recalculated in the helper's expected order.

```sh
restore_project=pilot-retry-check-1795220889
bash scripts/pilot_module_volumes.sh restore "$restore_project" "$backup_root/invalid"
docker volume ls -q --filter "label=com.docker.compose.project=$restore_project"
bash scripts/pilot_module_volumes.sh restore "$restore_project" "$backup_root/source"
bash scripts/pilot_module_volumes.sh backup "$restore_project" "$backup_root/restored"
```

The first restore exited with an error from tar (`invalid tar magic`). The
volume listing was empty. The retry and backup both exited successfully.
Comparison of all four archives confirmed matching file contents, entry types,
modes, owners, link targets, and non-directory modification times.

### Partial backup and concurrent publication

On Linux, `python3 -m unittest discover -s scripts/tests -p test_module_backup.py`
passed both regression tests. A Docker CLI fixture failed on the third archive
with exit 42. The destination and staging directory were absent afterwards.
Retrying the same path produced four archives with valid checksums. When a
second writer created the destination during backup, its marker was preserved.

A separate local Docker run restored the four saved module fixtures and ran
the commands below. All four checksums passed, the destination mode was 0700,
and repeating the backup returned an existing-destination error.

```sh
bash scripts/pilot_module_volumes.sh restore "$project" "$source_dir"
bash scripts/pilot_module_volumes.sh backup "$project" "$backup_root/new backup"
(cd "$backup_root/new backup" && sha256sum -c SHA256SUMS)
bash scripts/pilot_module_volumes.sh backup "$project" "$backup_root/new backup"
```
