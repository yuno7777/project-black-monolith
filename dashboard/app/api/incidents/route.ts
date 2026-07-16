// GET  /api/incidents — the investigation queue: ledger events joined with
//                       their triage state, filtered and worst-first.
// POST /api/incidents — apply a triage transition (assign / acknowledge /
//                       resolve) and append it to the audit trail.
//
// Unlike /api/ingest these are operator endpoints, not module endpoints, and
// they are deliberately unauthenticated: this dashboard has no user model, and
// a per-module bearer token would be the wrong credential for a human anyway.
// See the "Known limitations" note in the dashboard README — anything beyond a
// single-operator local stack needs a real identity layer in front of this.

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
import type { IncidentStatus, Severity } from "@/lib/types";
import { INCIDENT_STATUSES } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const params = new URL(req.url).searchParams;
  const query: IncidentQuery = {};

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

  const module = params.get("module");
  if (module && module !== "all") {
    if (!isKnownModule(module)) {
      return Response.json({ error: "unknown module filter" }, { status: 422 });
    }
    query.module = module;
  }

  const session = params.get("session");
  if (session) query.session = session.slice(0, 128);

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

  try {
    const [incidents, counts, crossLayer] = await Promise.all([
      listIncidents(query),
      incidentCounts(),
      crossLayerSessionCount(),
    ]);
    return Response.json({
      incidents,
      counts: { ...counts, cross_layer_sessions: crossLayer },
    });
  } catch (error) {
    console.error("failed to list incidents", error);
    return Response.json({ error: "the ledger is temporarily unavailable" }, { status: 503 });
  }
}

export async function POST(req: Request) {
  let body: unknown;
  try {
    body = JSON.parse(await req.text());
  } catch {
    return Response.json({ error: "invalid JSON" }, { status: 400 });
  }

  let transition;
  try {
    transition = normalizeTransition(body);
  } catch (error) {
    if (error instanceof IncidentInputError) {
      return Response.json({ error: error.message }, { status: 422 });
    }
    throw error;
  }

  try {
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
