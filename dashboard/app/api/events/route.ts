// GET /api/events — Server-Sent Events stream the browser subscribes to.
// On connect it replays the recent buffer, then streams every new event live.
//
// THE FLOW (browser -> this route -> stream)
// -----------------------------------------
//   Browser EventSource /api/events        (app/page.tsx useEffect)
//    -> requireOperator(req)               [route-auth.ts] viewer+ role
//    -> ensureLiveEventListener()          [live-event-listener.ts] — starts
//        the process-wide Postgres LISTEN connection (idempotent)
//    -> createEventStream(req, tenant_id)  [sse-event-stream.ts] — replay the
//        ledger, then stream live via the broker
//    -> Response with text/event-stream headers
//
// The route itself is thin: auth, ensure the listener, build the stream. All
// the interesting mechanics (subscribe-before-replay, Last-Event-ID resume,
// dedupe, keep-alive) live in sse-event-stream.ts — see that file.

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
