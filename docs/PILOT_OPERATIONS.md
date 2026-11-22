# GitHub triage pilot operations

Run one configured GitHub repository and one tenant per deployment. Keep
the database and module services private. Serve the dashboard and any remote
workload connections over HTTPS. Provision separate workload, operator, and
GitHub credentials through the deployment's secret store.

## Approval outcomes

The dashboard stores the repository, issue, proposed content, workload scope,
reviewer, timestamps, and GitHub response status. It records approval consumption
before contacting GitHub. The final dispatch and session revocation use the same
session lock. A request admitted to GitHub may finish before revocation commits.

Treat `uncertain`, or a `dispatching` action left after a crash, as work that
may have reached GitHub. Check the issue and existing comments before creating
a fresh proposal. The service never automatically resends a consumed approval.

## Backup and restore

Stop the dashboard, the alert dispatcher, and the three modules before making
a maintenance backup. Keep PostgreSQL running for the logical dump. Retain
the release archive and deployment configuration version with the backup.

```sh
pg_dump --format=custom --file=monolith.dump "$DATABASE_ADMIN_URL"
pg_restore --exit-on-error --single-transaction --dbname="$RESTORE_DATABASE_URL" monolith.dump
```

For the Docker Compose deployment, back up the four module volumes separately.
Use the original Compose project name to locate the volumes. Restore into a new
project with no module volumes and keep its services stopped until the database
and approval checks below pass.

```sh
docker compose -p monolith stop dashboard alert-dispatcher mcp-shield vector-anchor trace-audit
bash scripts/pilot_module_volumes.sh backup monolith ./module-backup
bash scripts/pilot_module_volumes.sh restore monolith-recovery ./module-backup
```

On Linux the backup helper stages the four archives in a private sibling
directory and publishes the destination once the checksum manifest is complete.
After an ordinary backup failure you can retry the same path. Existing backup
destinations are preserved.

The helper verifies every archive's SHA-256 before creating volumes and refuses
existing destinations. Restore only backups you trust. Keep the original named
volumes until recovery is verified. If extraction fails, the helper removes
volumes created by that restore so you can correct the backup and retry the
same project. If the host loses power or cleanup reports an error, use a fresh
recovery project and inspect the partial volumes before removing them. Keep the original MCP-Shield baseline key with the
release configuration so the restored baseline can still be validated.

Restore into a new database with the bootstrap roles in place. Start with the
GitHub credential absent and verify the restored ledger and approval history.
Expire pending approvals and mark interrupted dispatches uncertain on the
restored database before enabling a write credential. This avoids dispatching
an old approval whose result occurred after the backup.

```sql
update monolith.github_triage_actions
   set status = case when status = 'dispatching' then 'uncertain' else 'expired' end,
       finished_at = clock_timestamp()
 where status in ('pending', 'dispatching');
```

For deployments using the business workspace, apply the [business decision
recovery procedure](BUSINESS_CONTROL_CENTER.md#recover-after-a-database-restore)
before re-enabling its connector.

Reconcile the affected issues against GitHub before asking reviewers to approve
new proposals. Backups may contain drafts and operational evidence. Restrict
access to the same operators who can read that data in the dashboard.

## Upgrade and rollback

1. Verify the new archive checksum. Take a maintenance backup and retain the
   previous release archive.
2. Reuse the deployment credentials and data volumes. Run the new release's
   migrator and start the new dashboard and modules. Run `./monolith doctor`
   and confirm a read, proposal, review, and ledger lookup on a test issue.
3. To roll back this additive migration, stop the new release and redeploy the
   previous application against the same database. Leave the newer table in
   place to preserve review history. Keep the GitHub credential out of the
   rollback deployment. Restore a backup only if the database requires it.

Use the [developer quickstart](GITHUB_TRIAGE_QUICKSTART.md) for the pilot
workflow and the [verification report](PILOT_VERIFICATION.md) for gate results.
