# GitHub issue triage quickstart

Use a dedicated test repository with issues enabled. Create a test issue and a
label for the pilot. Give the dashboard a repository-scoped GitHub credential
with Issues write access. Give the agent only its Monolith workload token.

## Start the pilot

1. Verify the release archive with its `.zip.sha256` file, then extract it.
2. Run `./monolith init` in the extracted directory. Follow the [identity guide](IDENTITY_AND_ACCESS.md#authenticated-agent-workloads)
   to provision a workload grant for `triage-agent` and a new session ID.
3. Supply `MONOLITH_WORKLOAD_GRANTS_JSON` to the services and dashboard. Supply
   `MONOLITH_GITHUB_REPOSITORY=OWNER/REPOSITORY` and `MONOLITH_GITHUB_TOKEN` to the
   dashboard using your deployment secret store. Keep operator sign-in enabled.
4. Run `docker compose up -d --build --wait` and `./monolith doctor`. For the
   native Linux bundle, install Python 3.12, Node 22, and PostgreSQL 17 client
   tools, then run `sh packaging/install.sh`. Configure `DATABASE_ADMIN_URL`
   and the restricted runtime `DATABASE_URL` before starting with
   `.venv/bin/python scripts/run_local_demo.py --skip-build --skip-attacks`.

## Draft and review

Set `MONOLITH_DASHBOARD_API_URL` and supply the session's `MONOLITH_WORKLOAD_TOKEN`
to the agent process. Use HTTPS for a dashboard on another machine. Replace `1`
with the test issue number.

```sh
python3 scripts/github_triage_agent.py 1
python3 scripts/github_triage_agent.py 1 --add-label needs-review
python3 scripts/github_triage_agent.py 1 --reply-file draft.md
```

The sample agent reads issue data and submits a proposed action. An integration
can use `GET /api/github/issues/<number>` and `POST /api/github/triage` with the
same workload header. The proposal body contains a UUID `request_id`, the
numeric `issue`, and `action` with `kind` and `value`. Reuse the printed request
ID with `--request-id` to retry the same draft safely.

Sign in as an analyst or admin and open **GitHub approvals**. Read the exact
payload and select **Approve and send** or **Deny**. Check the result in the
queue and in GitHub. A proposal expires after 15 minutes. Use **Revoke session**
from a proposal to stop new calls by that workload. See the
[pilot operations runbook](PILOT_OPERATIONS.md) for recovery.

## Record live acceptance evidence

Use a disposable issue in the dedicated repository. Prepare two existing
labels, with the removal label attached and the addition label absent. Set
`MONOLITH_DASHBOARD_API_URL`, `MONOLITH_WORKLOAD_TOKEN`, and
`MONOLITH_VERIFY_GITHUB_TOKEN` for preparation. The verifier token only needs
permission to read the fixture issue and comments. Run from a clean test
workload session. Use a new private state file per run.

```sh
python3 scripts/verify_github_pilot.py prepare --test-repository OWNER/REPO \
  --issue 1 --state ./pilot-state.json \
  --label-to-add pilot-add --label-to-remove pilot-remove
```

In the dashboard, match the **Action ID** on each card to the ID printed by the
runner. Approve `reply`, `add_label`, and `remove_label`. Deny `denied`, then
revoke the test session using the `revoked` action.
Leave the `expired` action untouched. Set `MONOLITH_OPERATOR_TOKEN` to a test
analyst credential and run the immediate check before the 15-minute deadline.
Run the expiry check after that deadline. The checks exercise refused approval
attempts and compare the audit record with the actual GitHub comment and labels.

```sh
python3 scripts/verify_github_pilot.py check-now --test-repository OWNER/REPO \
  --issue 1 --state ./pilot-state.json --evidence ./pilot-now.json
python3 scripts/verify_github_pilot.py check-expired --test-repository OWNER/REPO \
  --issue 1 --state ./pilot-state.json --evidence ./pilot-expired.json
```

Each optional evidence file is created after its check passes. It records the
test target, verified checks, action IDs and digests, and audit outcomes. It
omits credentials, request headers, and the comment text. Use a new filename
for each successful check and keep both files with the pilot verification report.
