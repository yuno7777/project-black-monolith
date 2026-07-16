// GET /api/events — Server-Sent Events stream the browser subscribes to.
// On connect it replays the recent buffer, then streams every new event live.

import { getBroker } from "@/lib/event-ingest";
import { listRecentEvents } from "@/lib/event-store";
import type { MonolithEvent } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const broker = getBroker();
  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      let closed = false;
      const safeEnqueue = (chunk: string) => {
        if (closed) return;
        try {
          controller.enqueue(encoder.encode(chunk));
        } catch {
          closed = true;
        }
      };
      const send = (event: MonolithEvent) =>
        safeEnqueue(`data: ${JSON.stringify(event)}\n\n`);

      const unsubscribe = broker.subscribe(send);

      // Subscribe first, then replay the committed ledger. The client dedupes
      // by event_id, so an event committed during the query cannot be missed.
      try {
        const history = await listRecentEvents();
        for (const event of history.reverse()) send(event);
      } catch {
        safeEnqueue(`event: system\ndata: {"error":"history unavailable"}\n\n`);
      }

      // Keep-alive comment so intermediaries don't drop an idle connection.
      const keepAlive = setInterval(() => safeEnqueue(`: keep-alive\n\n`), 15000);

      const abort = () => {
        if (closed) return;
        closed = true;
        clearInterval(keepAlive);
        unsubscribe();
        try {
          controller.close();
        } catch {
          /* already closed */
        }
      };
      req.signal.addEventListener("abort", abort);
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
    },
  });
}
