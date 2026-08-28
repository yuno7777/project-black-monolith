// GET  /api/incidents — the investigation queue: ledger events joined with
//                       their triage state, filtered and worst-first.
// POST /api/incidents — apply a triage transition (assign / acknowledge /
//                       resolve) and append it to the audit trail.
//
// WHAT THIS FILE IS
// -----------------
// The route wrapper around incident-store.ts. GET powers the /investigate
// page; POST is what the IncidentPanel buttons call.
//
// THE PRINCIPAL SEPARATION (security)
// -----------------------------------
// These are operator (human) endpoints, NOT module endpoints, so they use the
// OPERATOR credential — a module token identifies a module and would let any
// module close its own findings. Reads require viewer; writes require analyst
// (admin implies analyst, analyst implies viewer).
//
// THE "DERIVED, NEVER DECLARED" RULE
// ----------------------------------
// The actor and tenant are derived from the credential (requireOperator's
// identity), never read from the request body: an identity a caller can name
// itself is not evidence. See normalizeTransition in incident-store.ts.
//
// ERROR SEMANTICS
// ---------------
//   401/403        wrong/missing operator credential or role
//   422            invalid filter (GET) or invalid transition (POST)
//   404            POST: no such event in the ledger (tenant-scoped — an
//                  event from another tenant is indistinguishable from an
//                  unknown id)
//   503            ledger/operator-auth unavailable (fail closed)

import {
  applyTransition,
  crossLayerSessionCount,
  incidentCounts,
  IncidentInputError,
  isKnownModule,
  isSeverity,
  listIncidents,
  normalizeTransition,
  UnknownEventError,
} from "@/lib/incident-store";
import type { IncidentQuery } from "@/lib/incident-store";
import { requireOperator } from "@/lib/route-auth";
import type { IncidentStatus, Severity } from "@/lib/types";
import { INCIDENT_STATUSES } from "@/lib/types";
import { jsonBodyError, readJsonBody } from "@/lib/request-body";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  // Called by: /investigate page (filters, search, pagination) and the
  // overview page's triage-badge polling (status=triaged&limit=500).
  const identity = await requireOperator(req);
  if (identity instanceof Response) return identity;
  const params = new URL(req.url).searchParams;
  // The tenant ALWAYS comes from the authenticated identity, never from a
  // query parameter — an operator cannot browse another tenant.
  const query: IncidentQuery = { tenant_id: identity.tenant_id };

  // Parse + bound every filter. Unknown values are 422s, not silent ignores.
  const status = params.get("status");
  if (status) {
    const pseudo = status === "open" || status === "all" || status === "triaged";
    if (!pseudo && !INCIDENT_STATUSES.includes(status as IncidentStatus)) {
      return Response.json({ error: "unknown status filter" }, { status: 422 });
    }
    query.status = status as IncidentQuery["status"];
  }

  const severity = params.get("severity");
  if (severity && severity !== "all") {
    if (!isSeverity(severity)) {
      return Response.json({ error: "unknown severity filter" }, { status: 422 });
    }
    query.severity = severity as Severity;
  }

  const moduleName = params.get("module");
  if (moduleName && moduleName !== "all") {
    if (!isKnownModule(moduleName)) {
      return Response.json({ error: "unknown module filter" }, { status: 422 });
    }
    query.module = moduleName;
  }

  const session = params.get("session");
  if (session) query.session = session.slice(0, 128);
  const agent = params.get("agent");
  if (agent) query.agent = agent.slice(0, 128);

  const q = params.get("q");
  if (q) query.q = q.slice(0, 256);

  const since = params.get("since_ms");
  if (since) {
    const parsed = Number(since);
    if (!Number.isFinite(parsed) || parsed < 0) {
      return Response.json({ error: "since_ms must be a positive number" }, { status: 422 });
    }
    query.since_ms = Math.trunc(parsed);
  }

  const limit = params.get("limit");
  if (limit) {
    const parsed = Number(limit);
    if (!Number.isFinite(parsed) || parsed < 1) {
      return Response.json({ error: "limit must be a positive number" }, { status: 422 });
    }
    query.limit = Math.trunc(parsed);
  }

  const cursor = params.get("cursor");
  if (cursor) query.cursor = cursor.slice(0, 512);

  // Three queries in parallel: the page itself, the tab counts, and the
  // cross-layer session counter (the "compromised agent" badge).
  try {
    const [page, counts, crossLayer] = await Promise.all([
      listIncidents(query),
      incidentCounts(identity.tenant_id),
      crossLayerSessionCount(identity.tenant_id),
    ]);
    return Response.json({
      incidents: page.incidents,
      next_cursor: page.next_cursor,
      counts: { ...counts, cross_layer_sessions: crossLayer },
    });
  } catch (error) {
    if (error instanceof IncidentInputError) {
      return Response.json({ error: error.message }, { status: 422 });
    }
    console.error("failed to list incidents", error);
    return Response.json({ error: "the ledger is temporarily unavailable" }, { status: 503 });
  }
}

export async function POST(req: Request) {
  // Called by: IncidentPanel buttons (assign/acknowledge/resolve/reopen).
  // Authenticate before parsing: an unauthenticated caller learns nothing about
  // whether its payload would have been valid.
  const identity = await requireOperator(req, "analyst");
  if (identity instanceof Response) return identity;

  let body: unknown;
  try {
    body = await readJsonBody(req, 16 * 1024);
  } catch (error) {
    return jsonBodyError(error) ?? Response.json({ error: "invalid JSON" }, { status: 400 });
  }

  let transition;
  try {
    // The actor comes from the credential, never from the body — a caller
    // cannot write someone else's name into the audit trail.
    transition = normalizeTransition(body, identity.actor, identity.tenant_id);
  } catch (error) {
    if (error instanceof IncidentInputError) {
      return Response.json({ error: error.message }, { status: 422 });
    }
    throw error;
  }

  try {
    // State change + audit row happen in ONE transaction (incident-store.ts).
    const { triage } = await applyTransition(transition);
    return Response.json({ event_id: transition.event_id, triage });
  } catch (error) {
    if (error instanceof UnknownEventError) {
      return Response.json({ error: "no such event in the ledger" }, { status: 404 });
    }
    console.error("failed to apply an incident transition", error);
    return Response.json({ error: "the ledger is temporarily unavailable" }, { status: 503 });
  }
}
