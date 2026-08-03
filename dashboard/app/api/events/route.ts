// GET /api/events — Server-Sent Events stream the browser subscribes to.
// On connect it replays the recent buffer, then streams every new event live.

import { requireOperator } from "@/lib/route-auth";
import { ensureLiveEventListener } from "@/lib/live-event-listener";
import { createEventStream } from "@/lib/sse-event-stream";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const identity = await requireOperator(req);
  if (identity instanceof Response) return identity;
  try {
    await ensureLiveEventListener();
  } catch (error) {
    console.error("failed to start live event delivery", error);
    return Response.json({ error: "live event delivery is unavailable" }, { status: 503 });
  }

  return new Response(createEventStream(req, identity.tenant_id), {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
    },
  });
}
