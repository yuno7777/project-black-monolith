import { withTenantDb } from "@/lib/db";
import { actionDigest, readIssue, TriageError, writeIssue, type GitHubAction, type githubConfig, type Workload } from "@/lib/github-triage";
import { lockSession, revokeSession, sessionRevokedIn } from "@/lib/incident-store";

type Status = "pending" | "denied" | "dispatching" | "succeeded" | "failed" | "uncertain" | "expired" | "revoked";
type TriageRow = {
  id: string;
  tenant_id: string;
  agent_id: string;
  session_id: string;
  repository: string;
  issue: number;
  kind: GitHubAction["kind"];
  value: string;
  digest: string;
  status: Status;
  expired: boolean;
};

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;

export function triageId(value: unknown): string {
  if (typeof value !== "string" || !UUID.test(value)) throw new TriageError(422, "an action UUID is required");
  return value;
}

export async function proposeAction(workload: Workload, requestId: string, repository: string, issue: number, action: GitHubAction) {
  const { tenant, agent, session } = workload;
  const digest = actionDigest(workload, repository, issue, action);
  return withTenantDb(tenant, async (db) => {
    await lockSession(db, tenant, agent, session);
    if (await sessionRevokedIn(db, tenant, agent, session)) throw new TriageError(403, "workload session is revoked");
    const inserted = await db.query<TriageRow>(
      `insert into monolith.github_triage_actions
         (tenant_id, agent_id, session_id, request_id, repository, issue, kind, value, digest)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       on conflict (tenant_id, agent_id, session_id, request_id) do nothing returning *`,
      [tenant, agent, session, requestId, repository, issue, action.kind, action.value, digest],
    );
    if (inserted.rows[0]) return inserted.rows[0];
    const existing = await db.query<TriageRow>(
      `select * from monolith.github_triage_actions
        where tenant_id = $1 and agent_id = $2 and session_id = $3 and request_id = $4`,
      [tenant, agent, session, requestId],
    );
    const row = existing.rows[0];
    if (row.digest !== digest) throw new TriageError(409, "this request ID is bound to another action");
    return row;
  });
}

export function listActions(tenant: string, before?: string) {
  return withTenantDb(tenant, async (db) => {
    const result = await db.query<TriageRow>(
      `select actions.*, (expires_at <= clock_timestamp()) as expired,
              (select r.revoked_at from monolith.revoked_sessions r where r.tenant_id = actions.tenant_id
                and r.agent_id = actions.agent_id and r.session_id = actions.session_id
                and r.restored_at is null) as session_revoked_at
         from monolith.github_triage_actions actions where tenant_id = $1
          and ($2::uuid is null or (created_at, id) < (
            select created_at, id from monolith.github_triage_actions where tenant_id = $1 and id = $2
          ))
        order by created_at desc, id desc limit 51`, [tenant, before ?? null],
    );
    const rows = result.rows.slice(0, 50);
    return {
      actions: rows.map((row) => row.status === "pending" && row.expired ? { ...row, status: "expired" } : row),
      next: result.rows.length > rows.length ? rows.at(-1)?.id : null,
    };
  });
}

export async function revokeActionSession(tenant: string, id: string, digest: string, reviewer: string) {
  const row = await withTenantDb(tenant, async (db) => {
    const result = await db.query<TriageRow>(
      "select * from monolith.github_triage_actions where tenant_id = $1 and id = $2", [tenant, id],
    );
    return result.rows[0];
  });
  if (!row) throw new TriageError(404, "action not found");
  if (row.digest !== digest) throw new TriageError(409, "the action does not match the review");
  return revokeSession(tenant, row.agent_id, row.session_id, `Revoked from GitHub approval ${id}`, reviewer);
}

export async function reviewAction(
  config: ReturnType<typeof githubConfig>, id: string, digest: string, decision: "approve" | "deny", reviewer: string,
) {
  const { tenant } = config;
  const claimed = await withTenantDb(tenant, async (db) => {
    const result = await db.query<TriageRow>(
      `select *, (expires_at <= clock_timestamp()) as expired from monolith.github_triage_actions
        where tenant_id = $1 and id = $2 for update`, [tenant, id],
    );
    const row = result.rows[0];
    if (!row) throw new TriageError(404, "action not found");
    if (row.digest !== digest || row.repository !== config.repository) {
      throw new TriageError(409, "the action does not match the review");
    }
    if (row.status !== "pending") throw new TriageError(409, "the action has already been decided");
    const status = row.expired ? "expired" : decision === "deny" ? "denied" : "dispatching";
    const updated = await db.query<TriageRow>(
      `update monolith.github_triage_actions set status = $3, reviewer = $4,
              reviewed_at = clock_timestamp(), finished_at = case when $3 <> 'dispatching' then clock_timestamp() end
        where tenant_id = $1 and id = $2 returning *`, [tenant, id, status, reviewer],
    );
    return updated.rows[0];
  });
  if (claimed.status !== "dispatching") return claimed;

  // Commit consumption before contacting GitHub. Replay after a crash can
  // inspect a dispatching record, but must never issue another write.
  return withTenantDb(tenant, async (db) => {
    await lockSession(db, tenant, claimed.agent_id, claimed.session_id);
    const result = await db.query<{ expired: boolean }>(
      `select expires_at <= clock_timestamp() as expired from monolith.github_triage_actions
        where tenant_id = $1 and id = $2`, [tenant, id],
    );
    let status: Status = "failed";
    let githubStatus: number | null = null;
    let commentId: string | null = null;
    if (result.rows[0].expired) {
      status = "expired";
    } else if (await sessionRevokedIn(db, tenant, claimed.agent_id, claimed.session_id)) {
      status = "revoked";
    } else {
      let issueConfirmed = false;
      try {
        await readIssue(config, claimed.issue);
        issueConfirmed = true;
      } catch {
        // No write was attempted.
      }
      if (issueConfirmed) {
        const deadline = await db.query<{ expired: boolean }>(
          `select expires_at <= clock_timestamp() as expired from monolith.github_triage_actions
            where tenant_id = $1 and id = $2`, [tenant, id],
        );
        if (deadline.rows[0].expired) {
          status = "expired";
        } else {
          status = "uncertain";
          try {
            const outcome = await writeIssue(config, claimed.issue, { kind: claimed.kind, value: claimed.value });
            githubStatus = outcome.status;
            commentId = outcome.commentId;
            const expected = claimed.kind === "reply" ? 201 : 200;
            if (githubStatus === expected) status = "succeeded";
            else if (githubStatus >= 400 && githubStatus < 500 && githubStatus !== 408) status = "failed";
          } catch {
            // Transport or response failure can follow an accepted write.
          }
        }
      }
    }
    const updated = await db.query<TriageRow>(
      `update monolith.github_triage_actions set status = $3, finished_at = clock_timestamp(),
              github_status = $4, github_comment_id = $5 where tenant_id = $1 and id = $2 returning *`,
      [tenant, id, status, githubStatus, commentId],
    );
    return updated.rows[0];
  });
}
