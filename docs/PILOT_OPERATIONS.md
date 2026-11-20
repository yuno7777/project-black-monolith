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

Stop the dashboard and any dispatching processes before making a maintenance
backup. Back up PostgreSQL and the configured persistent module volumes. Keep
the release archive and deployment configuration version with the backup.

```sh
pg_dump --format=custom --file=monolith.dump "$DATABASE_ADMIN_URL"
pg_restore --exit-on-error --single-transaction --dbname="$RESTORE_DATABASE_URL" monolith.dump
```

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
