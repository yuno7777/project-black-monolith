// GET /api/sessions/revoked — the revocation snapshot modules poll when no
// events are flowing. Authenticated with the caller's per-module ingest token
// (the same credential it already uses to POST events), scoped to a tenant.
//
// The snapshot is paged. A module reads a response body under a hard byte
// cap, and a snapshot larger than that cap cannot be parsed at all: the
// module keeps the set it already had, and that set is stale. Past a certain
// number of live revocations every snapshot is too large, so the staleness
// never ends and the circuit breaker fails open for exactly the sessions it
// was meant to quarantine. One page is always small enough to read, and a
// client that follows the pages gets the whole set.

import {
  countRevokedSessions,
  decodeRevocationCursor,
  encodeRevocationCursor,
  listRevokedSessionPage,
  MAX_REVOCATION_PAGE_IDS,
  MAX_REVOCATION_SNAPSHOT_BYTES,
  type RevocationCursor,
} from "@/lib/incident-store";
import { authenticateIngest } from "@/lib/ingest-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const KNOWN_MODULES = new Set(["mcp-shield", "vector-anchor", "trace-audit"]);

/** The cursor that starts before the first revoked session. */
const START_CURSOR = encodeRevocationCursor("", "");

class BadRequest extends Error {}

/** How many ids one page may carry. */
function readLimit(raw: string | null): number {
  if (raw === null) return MAX_REVOCATION_PAGE_IDS;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 1 || value > MAX_REVOCATION_PAGE_IDS) {
    throw new BadRequest(`limit must be a whole number between 1 and ${MAX_REVOCATION_PAGE_IDS}`);
  }
  return value;
}

/**
 * The whole set, when it is small enough to carry in one response.
 *
 * The set is assembled from the pages, so the answer is complete; the
 * assembly stops as soon as it is clear that the set cannot fit, because the
 * client is going to page it anyway.
 */
async function assembleSnapshot(
  tenantId: string,
  limit: number,
): Promise<{ ids: string[] | null; total: number }> {
  const ids: string[] = [];
  const seen = new Set<string>();
  let bytes = 0;
  let cursor: RevocationCursor | undefined;
  for (;;) {
    const page = await listRevokedSessionPage(tenantId, cursor, limit);
    for (const id of page.session_ids) {
      if (seen.has(id)) continue;
      seen.add(id);
      ids.push(id);
      bytes += id.length + 3;
    }
    if (bytes > MAX_REVOCATION_SNAPSHOT_BYTES) {
      // The set does not fit in one response. The client is told so, and
      // given the cursor that starts the pages.
      return { ids: null, total: await countRevokedSessions(tenantId) };
    }
    if (!page.next_cursor) break;
    cursor = decodeRevocationCursor(page.next_cursor);
  }
  return { ids, total: await countRevokedSessions(tenantId) };
}

export async function GET(req: Request) {
  const tenant = req.headers.get("x-monolith-tenant-id")?.trim() ?? "";
  const moduleName = req.headers.get("x-monolith-module")?.trim() ?? "";
  if (!tenant || tenant.length > 128 || !KNOWN_MODULES.has(moduleName)) {
    return Response.json({ error: "a known module and tenant are required" }, { status: 401 });
  }
  try {
    if (!authenticateIngest(req, tenant, moduleName)) {
      return Response.json({ error: "invalid module credential" }, { status: 401 });
    }
  } catch (error) {
    console.error("revocation snapshot authentication is misconfigured", error);
    return Response.json({ error: "authentication is unavailable" }, { status: 503 });
  }

  const url = new URL(req.url);
  const rawCursor = url.searchParams.get("cursor");
  const rawLimit = url.searchParams.get("limit");
  let limit: number;
  try {
    limit = readLimit(rawLimit);
  } catch (error) {
    return Response.json(
      { error: error instanceof Error ? error.message : "invalid limit" },
      { status: 422 },
    );
  }

  try {
    if (rawCursor !== null) {
      let cursor: RevocationCursor;
      try {
        cursor = decodeRevocationCursor(rawCursor);
      } catch {
        return Response.json({ error: "cursor is invalid or expired" }, { status: 422 });
      }
      const page = await listRevokedSessionPage(tenant, cursor, limit);
      return Response.json({
        tenant_id: tenant,
        generated_at_ms: Date.now(),
        // A page is never the whole set, and a client that treats it as one
        // would silently forget every revocation that is not on it.
        revoked_sessions: page.session_ids,
        revoked_sessions_complete: false,
        next_cursor: page.next_cursor ?? null,
      });
    }

    const snapshot = await assembleSnapshot(tenant, limit);
    if (snapshot.ids === null) {
      return Response.json({
        tenant_id: tenant,
        generated_at_ms: Date.now(),
        revoked_sessions: null,
        revoked_sessions_complete: false,
        revoked_sessions_total: snapshot.total,
        next_cursor: START_CURSOR,
      });
    }
    return Response.json({
      tenant_id: tenant,
      generated_at_ms: Date.now(),
      revoked_sessions: snapshot.ids,
      revoked_sessions_complete: true,
      revoked_sessions_total: snapshot.total,
      next_cursor: null,
    });
  } catch (error) {
    console.error("failed to read revoked sessions", error);
    return Response.json({ error: "the ledger is temporarily unavailable" }, { status: 503 });
  }
}
