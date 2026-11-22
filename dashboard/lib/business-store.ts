import { createHash } from "node:crypto";
import type { PoolClient } from "pg";
import {
  BUSINESS_TEMPLATES, DEFAULT_BUSINESS_POLICY, evaluateBusinessAction,
  parseBusinessAction, parseBusinessPolicy, validateTemplateAction,
  type BusinessAction, type BusinessActionKind, type BusinessPolicy, type BusinessTemplateId,
} from "@/lib/business-policy";
import { withTenantDb } from "@/lib/db";
import { TriageError, type Workload } from "@/lib/github-triage";
import { lockSession, sessionRevokedIn } from "@/lib/incident-store";

const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
type Status = "pending" | "dispatching" | "denied" | "changes_requested" | "succeeded" |
  "failed" | "uncertain" | "expired" | "stale" | "revoked";

export type BusinessDecision = {
  id: string; case_id: string; template_id: BusinessTemplateId; agent_id: string; session_id: string;
  action: BusinessAction; digest: string; reviewer_team: string; reason: string; status: Status;
  reviewer: string | null; reference: string | null; created_at: string; expires_at: string; reviewed_at: string | null;
};

export type BusinessAgent = {
  agent_id: string; owner: string; allowed_kinds: BusinessActionKind[]; paused: boolean; practice_only: boolean;
  updated_at: string; last_activity: string | null;
};

type Activity = { id: string; decision_id: string | null; actor: string; event: string; note: string; created_at: string };
type Report = {
  pending: number; denied: number; changes_requested: number; uncertain: number;
  succeeded: number; overdue: number; mean_review_seconds: number | null;
};

async function audit(db: PoolClient, tenant: string, actor: string, event: string, note: string, id?: string) {
  await db.query(`insert into monolith.business_activity (tenant_id,actor,event,note,decision_id)
    values ($1,$2,$3,$4,$5)`, [tenant, actor, event, note, id ?? null]);
}

// Configuration updates and irreversible dispatches share this lock order. Reads can
// proceed concurrently; a completed permission change always precedes the next dispatch.
async function lockConfig(db: PoolClient, tenant: string, editing = false) {
  const fn = editing ? "pg_advisory_xact_lock" : "pg_advisory_xact_lock_shared";
  await db.query(`select ${fn}(hashtextextended($1, 1))`, [tenant]);
}

async function currentPolicy(db: PoolClient, tenant: string): Promise<BusinessPolicy> {
  const result = await db.query("select policy from monolith.business_policies where tenant_id=$1", [tenant]);
  return result.rows[0] ? parseBusinessPolicy(result.rows[0].policy) : DEFAULT_BUSINESS_POLICY;
}

async function invalidate(db: PoolClient, tenant: string, actor: string, agent?: string) {
  // A stranded dispatch may already have reached the provider. Keep it in
  // reconciliation, even when the configuration changes during recovery.
  await db.query(`with changed as (
    update monolith.business_decisions set status=case when status='pending' then 'stale' else 'uncertain' end
    where tenant_id=$1 and status in ('pending','dispatching') and ($2::text is null or agent_id=$2)
    returning id,status)
    insert into monolith.business_activity (tenant_id,decision_id,actor,event,note)
    select $1,id,$3,status,'Agent or policy configuration changed.' from changed`,
    [tenant, agent ?? null, actor]);
}

export type AgentSettings = {agentId: string; owner: string; allowedKinds: BusinessActionKind[]; paused: boolean; practiceOnly?: boolean};
export function saveBusinessAgent(tenant: string, actor: string, input: AgentSettings) {
  const kinds = new Set<string>(BUSINESS_TEMPLATES.flatMap(t => [...t.actionKinds]));
  if (typeof input.agentId !== "string" || !ID.test(input.agentId) || typeof input.owner !== "string" || !input.owner.trim() ||
      input.owner.length > 128 || input.owner.includes("\0") || typeof input.paused !== "boolean" ||
      (input.practiceOnly !== undefined && typeof input.practiceOnly !== "boolean") ||
      !Array.isArray(input.allowedKinds) || input.allowedKinds.length > kinds.size ||
      input.allowedKinds.some(kind => !kinds.has(kind)) || new Set(input.allowedKinds).size !== input.allowedKinds.length) {
    throw new TriageError(422, "invalid agent settings");
  }
  return withTenantDb(tenant, async db => {
    await lockConfig(db, tenant, true);
    const result = await db.query(`insert into monolith.business_agents as a (tenant_id,agent_id,owner,allowed_kinds,paused,practice_only)
      values ($1,$2,$3,$4,$5,$6) on conflict (tenant_id,agent_id) do update
      set owner=excluded.owner,allowed_kinds=excluded.allowed_kinds,paused=excluded.paused,practice_only=excluded.practice_only,updated_at=clock_timestamp()
      where (a.owner,a.allowed_kinds,a.paused,a.practice_only) is distinct from (excluded.owner,excluded.allowed_kinds,excluded.paused,excluded.practice_only)
      returning agent_id`, [tenant, input.agentId, input.owner.trim(), [...input.allowedKinds].sort(), input.paused,input.practiceOnly ?? true]);
    if (result.rowCount) {
      await invalidate(db, tenant, actor, input.agentId);
      await audit(db, tenant, actor, "agent_updated", input.agentId);
    }
    return {agentId: input.agentId};
  });
}

export function saveBusinessPolicy(tenant: string, actor: string, value: BusinessPolicy) {
  const policy = parseBusinessPolicy(value);
  return withTenantDb(tenant, async db => {
    await lockConfig(db, tenant, true);
    const result = await db.query(`insert into monolith.business_policies as p (tenant_id,policy)
      values ($1,$2) on conflict (tenant_id) do update set policy=excluded.policy
      where p.policy is distinct from excluded.policy returning tenant_id`, [tenant, policy]);
    if (result.rowCount) {
      await invalidate(db, tenant, actor);
      await audit(db, tenant, actor, "policy_updated", JSON.stringify(policy));
    }
    return policy;
  });
}

async function agentPermitted(db: PoolClient, tenant: string, agent: string, kind: BusinessActionKind, practice = false) {
  const {rowCount} = await db.query(`select 1 from monolith.business_agents where tenant_id=$1
    and agent_id=$2 and not paused and ($4 or not practice_only) and $3=any(allowed_kinds)`, [tenant, agent, kind, practice]);
  return rowCount === 1;
}

export type BusinessProposal = {requestId: string; caseId: string; templateId: BusinessTemplateId; action: BusinessAction};
export function proposeBusinessAction(workload: Workload, input: BusinessProposal) {
  if (!UUID.test(input.requestId) || typeof input.caseId !== "string" || !ID.test(input.caseId)) {
    throw new TriageError(422, "a request UUID and valid case identifier are required");
  }
  const action = parseBusinessAction(input.action);
  const template = validateTemplateAction(input.templateId, action);
  const {tenant, agent, session} = workload;
  const digest = createHash("sha256").update(JSON.stringify([tenant,agent,session,input.requestId.toLowerCase(),
    input.caseId,template,action])).digest("hex");
  return withTenantDb(tenant, async db => {
    await lockConfig(db, tenant);
    await lockSession(db, tenant, agent, session);
    if (await sessionRevokedIn(db, tenant, agent, session) || !(await agentPermitted(db, tenant, agent, action.kind))) {
      throw new TriageError(403, "workload cannot propose this action");
    }
    const existing = await db.query<BusinessDecision>(`select * from monolith.business_decisions
      where tenant_id=$1 and agent_id=$2 and session_id=$3 and request_id=$4`, [tenant, agent, session, input.requestId]);
    if (existing.rows[0]) {
      if (existing.rows[0].digest !== digest) throw new TriageError(409, "request ID already belongs to another proposal");
      return existing.rows[0];
    }
    await db.query(`insert into monolith.business_cases (tenant_id,case_id,template_id)
      values ($1,$2,$3) on conflict do nothing`, [tenant, input.caseId, template]);
    const found = await db.query("select template_id from monolith.business_cases where tenant_id=$1 and case_id=$2", [tenant,input.caseId]);
    if (found.rows[0].template_id !== template) throw new TriageError(409, "case belongs to another workflow");
    if (action.kind === "customer_reply" && action.afterRefundId) {
      const dependency = await db.query(`select 1 from monolith.business_decisions where tenant_id=$1 and id=$2
        and case_id=$3 and action->>'kind'='refund' and status='succeeded'`,
        [tenant,action.afterRefundId,input.caseId]);
      if (!dependency.rowCount) throw new TriageError(409, "customer reply requires a confirmed refund in this case");
    }
    const rule = evaluateBusinessAction(action, await currentPolicy(db, tenant));
    const result = await db.query<BusinessDecision>(`insert into monolith.business_decisions
      (tenant_id,agent_id,session_id,request_id,case_id,template_id,action,digest,reviewer_team,reason)
      values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) returning *`,
      [tenant,agent,session,input.requestId,input.caseId,template,action,digest,rule.reviewerTeam,rule.reason]);
    await audit(db, tenant, agent, "proposed", rule.reason, result.rows[0].id);
    return result.rows[0];
  });
}

export function readBusinessPolicy(tenant: string) {
  return withTenantDb(tenant, db => currentPolicy(db, tenant));
}

export function practiceBusinessAction(workload: Workload, input: {templateId: BusinessTemplateId; action: BusinessAction}) {
  const action = parseBusinessAction(input.action);
  validateTemplateAction(input.templateId, action);
  const {tenant, agent, session} = workload;
  return withTenantDb(tenant, async db => {
    await lockConfig(db, tenant);
    await lockSession(db, tenant, agent, session);
    if (await sessionRevokedIn(db, tenant, agent, session) || !(await agentPermitted(db, tenant, agent, action.kind, true))) {
      throw new TriageError(403, "workload cannot practice this action");
    }
    return {ok:true, ...evaluateBusinessAction(action, await currentPolicy(db, tenant))};
  });
}

type Review = {
  id: string; digest: string; decision: "approve" | "deny" | "request_changes" | "confirm" | "not_applied"; note?: string;
};
export type DispatchOutcome = {status: "succeeded" | "failed" | "uncertain"; reference?: string};

export async function reviewBusinessAction(tenant: string, actor: string, teams: string[], input: Review,
  dispatch: (id: string, action: BusinessAction) => Promise<DispatchOutcome>) {
  const reconcile = input.decision === "confirm" || input.decision === "not_applied";
  if (!UUID.test(input.id) || !/^[0-9a-f]{64}$/.test(input.digest) ||
      !["approve","deny","request_changes","confirm","not_applied"].includes(input.decision) ||
      (input.note !== undefined && (typeof input.note !== "string" || input.note.length > 1000 || input.note.includes("\0"))) ||
      ((reconcile || input.decision === "request_changes") && !input.note?.trim())) {
    throw new TriageError(422, "invalid review or missing review note");
  }
  const claimed = await withTenantDb(tenant, async db => {
    await lockConfig(db, tenant);
    const {rows} = await db.query<BusinessDecision & {expired: boolean; stranded: boolean}>(`select *,
      expires_at<=clock_timestamp() as expired, reviewed_at<clock_timestamp()-interval '1 minute' as stranded
      from monolith.business_decisions where tenant_id=$1 and id=$2 for update`, [tenant,input.id]);
    const row = rows[0];
    if (!row) throw new TriageError(404, "decision not found");
    if (!teams.includes(row.reviewer_team)) throw new TriageError(403, "reviewer team does not match the policy");
    if (row.digest !== input.digest) throw new TriageError(409, "proposal does not match the review");
    if (reconcile) {
      if (row.status !== "uncertain" && !(row.status === "dispatching" && row.stranded)) {
        throw new TriageError(409, "only an uncertain or interrupted action may be reconciled");
      }
      const status = input.decision === "confirm" ? "succeeded" : "failed";
      const result = await db.query<BusinessDecision>(`update monolith.business_decisions set status=$3
        where tenant_id=$1 and id=$2 returning *`, [tenant,input.id,status]);
      await audit(db, tenant, actor, `reconciled_${status}`, input.note!.trim(), input.id);
      return result.rows[0];
    }
    if (row.status !== "pending") throw new TriageError(409, "proposal is no longer pending");
    const status = row.expired ? "expired" : input.decision === "approve" ? "dispatching" :
      input.decision === "deny" ? "denied" : "changes_requested";
    // The partial unique index also serializes two different refund proposals for the same case.
    const result = await db.query<BusinessDecision>(`update monolith.business_decisions
      set status=$3,reviewer=$4,reviewed_at=clock_timestamp() where tenant_id=$1 and id=$2 returning *`,
      [tenant,input.id,status,actor]);
    await audit(db, tenant, actor, status, input.note?.trim() || "", input.id);
    return result.rows[0];
  }).catch((error: unknown) => {
    if (typeof error === "object" && error !== null && "constraint" in error && error.constraint === "business_case_one_refund") {
      throw new TriageError(409, "a refund has already been dispatched for this case");
    }
    throw error;
  });
  if (claimed.status !== "dispatching") return claimed;

  // Consumption is durable before starting I/O. A crash after the provider
  // receives the action leaves a reconcilable record that cannot be replayed.
  return withTenantDb(tenant, async db => {
    await lockConfig(db, tenant);
    await lockSession(db, tenant, claimed.agent_id, claimed.session_id);
    const {rows} = await db.query<BusinessDecision & {expired: boolean}>(`select *,expires_at<=clock_timestamp() as expired
      from monolith.business_decisions where tenant_id=$1 and id=$2 for update`, [tenant,input.id]);
    const row = rows[0];
    if (row.status !== "dispatching") return row;
    let status: Status;
    let reference: string | null = null;
    if (await sessionRevokedIn(db, tenant, row.agent_id, row.session_id)) status = "revoked";
    else if (!(await agentPermitted(db, tenant, row.agent_id, row.action.kind))) status = "stale";
    else if (row.expired) status = "expired";
    else {
      try {
        const outcome = await dispatch(row.id, row.action);
        status = outcome.status;
        reference = outcome.reference ?? null;
      } catch {
        status = "uncertain";
      }
    }
    const result = await db.query<BusinessDecision>(`update monolith.business_decisions set status=$3,reference=$4
      where tenant_id=$1 and id=$2 returning *`, [tenant,row.id,status,reference]);
    await audit(db, tenant, actor, status, reference ?? "", row.id);
    return result.rows[0];
  });
}

type WorkspacePage = {before?: string; activityBefore?: string; status?: string; id?: string};

export function businessWorkspace(tenant: string, page: WorkspacePage = {}) {
  if ([page.before,page.activityBefore,page.id].some(value => value !== undefined && !UUID.test(value)) ||
      (page.status !== undefined && !["pending","dispatching","denied","changes_requested","succeeded","failed",
        "uncertain","expired","stale","revoked","needs_review"].includes(page.status))) {
    throw new TriageError(422, "invalid decision status or cursor");
  }
  return withTenantDb(tenant, async db => {
    const agents = await db.query<BusinessAgent>(`select a.*,(select max(d.created_at) from monolith.business_decisions d
      where d.tenant_id=a.tenant_id and d.agent_id=a.agent_id) as last_activity
      from monolith.business_agents a where tenant_id=$1 order by agent_id`, [tenant]);
    const policy = await currentPolicy(db, tenant);
    const decisions = await db.query<BusinessDecision & {effective_status: Status}>(`select d.*,s.effective_status
      from monolith.business_decisions d cross join lateral (select case
        when status='pending' and expires_at<=now() then 'expired'
        when status='dispatching' and reviewed_at<now()-interval '1 minute' then 'uncertain'
        else status end as effective_status) s
      where d.tenant_id=$1 and ($2::uuid is null or (d.created_at,d.id)<(
        select created_at,id from monolith.business_decisions where tenant_id=$1 and id=$2))
        and ($3::text is null or effective_status=$3 or ($3='needs_review' and effective_status in ('pending','uncertain')))
        and ($4::uuid is null or d.id=$4)
      order by d.created_at desc,d.id desc limit 51`, [tenant,page.before ?? null,page.status ?? null,page.id ?? null]);
    const activity = await db.query<Activity>(`select * from monolith.business_activity a where tenant_id=$1
      and ($2::uuid is null or (a.created_at,a.id)<(
        select created_at,id from monolith.business_activity where tenant_id=$1 and id=$2))
      order by created_at desc,id desc limit 101`, [tenant,page.activityBefore ?? null]);
    const report = await db.query<Report>(`select
      count(*) filter(where status='pending' and expires_at>now())::integer as pending,
      count(*) filter(where status='expired' or (status='pending' and expires_at<=now()))::integer as overdue,
      count(*) filter(where status='denied')::integer as denied,
      count(*) filter(where status='changes_requested')::integer as changes_requested,
      count(*) filter(where status='uncertain' or (status='dispatching' and reviewed_at<now()-interval '1 minute'))::integer as uncertain,
      count(*) filter(where status='succeeded')::integer as succeeded,
      avg(extract(epoch from reviewed_at-created_at))::float8 as mean_review_seconds
      from monolith.business_decisions where tenant_id=$1`, [tenant]);
    return {agents: agents.rows, policy, decisions: decisions.rows.slice(0,50).map(row => ({...row,status:row.effective_status})),
      activity: activity.rows.slice(0,100), report: report.rows[0],
      next: decisions.rows.length > 50 ? decisions.rows[49].id : null,
      activityNext: activity.rows.length > 100 ? activity.rows[99].id : null};
  });
}

export type BusinessWorkspace = Awaited<ReturnType<typeof businessWorkspace>>;
