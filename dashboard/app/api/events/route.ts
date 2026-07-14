// GET /api/events — Server-Sent Events stream the browser subscribes to.
// On connect it replays the recent buffer, then streams every new event live.

import { getBroker } from "@/lib/event-ingest";
import type { MonolithEvent } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const broker = getBroker();
  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    start(controller) {
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

      // Replay recent history so a freshly-opened dashboard isn't empty.
      for (const event of broker.recent()) send(event);

      const unsubscribe = broker.subscribe(send);

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
