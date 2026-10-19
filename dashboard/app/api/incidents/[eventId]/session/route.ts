// GET /api/incidents/<event_id>/session — what else happened in this event's
// agent session, broken down by defense layer.
// POST /api/incidents/<event_id>/session — manually quarantine (revoke) the session.
// DELETE /api/incidents/<event_id>/session — restore a quarantined session.

import {
  IncidentInputError,
  restoreSession,
  revokeSession,
  sessionForEvent,
} from "@/lib/incident-store";
import { jsonBodyError, readJsonBody } from "@/lib/request-body";
import { requireOperator } from "@/lib/route-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function GET(req: Request, context: { params: Promise<{ eventId: string }> }) {
  const identity = await requireOperator(req);
  if (identity instanceof Response) return identity;
  const { eventId } = await context.params;
  if (!UUID_PATTERN.test(eventId)) {
    return Response.json({ error: "event_id must be a UUID" }, { status: 422 });
  }
  try {
    const session = await sessionForEvent(eventId, identity.tenant_id);
    if (!session) {
      return Response.json(
        { error: "this event carries no complete agent/session identity, so it cannot be correlated" },
        { status: 404 },
      );
    }
    return Response.json({ session });
  } catch (error) {
    console.error("failed to read an event's session", error);
    return Response.json({ error: "the ledger is temporarily unavailable" }, { status: 503 });
  }
}

export async function POST(req: Request, context: { params: Promise<{ eventId: string }> }) {
  const identity = await requireOperator(req, "analyst");
  if (identity instanceof Response) return identity;
  const { eventId } = await context.params;
  if (!UUID_PATTERN.test(eventId)) {
    return Response.json({ error: "event_id must be a UUID" }, { status: 422 });
  }

  let reason = "Manual operator session quarantine";
  const contentLength = req.headers.get("content-length");
  if (contentLength && contentLength !== "0") {
    try {
      const body = (await readJsonBody(req, 8 * 1024)) as { reason?: unknown } | null;
      if (body && typeof body.reason === "string" && body.reason.trim()) {
        reason = body.reason.trim();
      }
    } catch (error) {
      return jsonBodyError(error) ?? Response.json({ error: "invalid JSON" }, { status: 400 });
    }
  } else {
    try {
      const rawText = await req.text();
      if (rawText.trim()) {
        const parsed = JSON.parse(rawText) as { reason?: unknown };
        if (parsed && typeof parsed.reason === "string" && parsed.reason.trim()) {
          reason = parsed.reason.trim();
        }
      }
    } catch {
      return Response.json({ error: "invalid JSON" }, { status: 400 });
    }
  }

  try {
    const current = await sessionForEvent(eventId, identity.tenant_id);
    if (!current) {
      return Response.json(
        { error: "this event carries no complete agent/session identity, so it cannot be correlated" },
        { status: 404 },
      );
    }
    await revokeSession(
      identity.tenant_id,
      current.agent_id,
      current.session_id,
      reason,
      identity.actor,
      current.layers.map((layer) => layer.module),
    );
    const updated = await sessionForEvent(eventId, identity.tenant_id);
    return Response.json({ session: updated });
  } catch (error) {
    if (error instanceof IncidentInputError) {
      return Response.json({ error: error.message }, { status: 422 });
    }
    console.error("failed to quarantine agent session", error);
    return Response.json({ error: "the ledger is temporarily unavailable" }, { status: 503 });
  }
}

export async function DELETE(req: Request, context: { params: Promise<{ eventId: string }> }) {
  const identity = await requireOperator(req, "analyst");
  if (identity instanceof Response) return identity;
  const { eventId } = await context.params;
  if (!UUID_PATTERN.test(eventId)) {
    return Response.json({ error: "event_id must be a UUID" }, { status: 422 });
  }

  try {
    const current = await sessionForEvent(eventId, identity.tenant_id);
    if (!current) {
      return Response.json(
        { error: "this event carries no complete agent/session identity, so it cannot be correlated" },
        { status: 404 },
      );
    }
    await restoreSession(identity.tenant_id, current.agent_id, current.session_id);
    const updated = await sessionForEvent(eventId, identity.tenant_id);
    return Response.json({ session: updated });
  } catch (error) {
    if (error instanceof IncidentInputError) {
      return Response.json({ error: error.message }, { status: 422 });
    }
    console.error("failed to restore agent session", error);
    return Response.json({ error: "the ledger is temporarily unavailable" }, { status: 503 });
  }
}
