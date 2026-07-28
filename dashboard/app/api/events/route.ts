// GET /api/events — Server-Sent Events stream the browser subscribes to.
// On connect it replays the recent buffer, then streams every new event live.

import { requireOperator } from "@/lib/route-auth";
import { createEventStream } from "@/lib/sse-event-stream";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const identity = await requireOperator(req);
  if (identity instanceof Response) return identity;

  return new Response(createEventStream(req, identity.tenant_id), {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
    },
  });
}
