import { getBroker } from "@/lib/event-ingest";
import { listRecentEvents } from "@/lib/event-store";
import type { MonolithEvent } from "@/lib/types";

interface EventBrokerLike {
  subscribe(tenantId: string, subscriber: (event: MonolithEvent) => void): () => void;
}

export function createEventStream(
  req: Request,
  tenantId: string,
  broker: EventBrokerLike = getBroker(),
  loadHistory: (tenantId: string) => Promise<MonolithEvent[]> = listRecentEvents,
): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  let cleanup: (closeController?: boolean) => void = () => {};

  const stream = new ReadableStream({
    async start(controller) {
      let closed = false;
      let cleaned = false;
      let keepAlive: ReturnType<typeof setInterval> | undefined;
      let unsubscribe = () => {};
      const abort = () => cleanup();

      cleanup = (closeController = true) => {
        if (cleaned) return;
        cleaned = true;
        closed = true;
        if (keepAlive) clearInterval(keepAlive);
        unsubscribe();
        req.signal.removeEventListener("abort", abort);
        if (!closeController) return;
        try {
          controller.close();
        } catch {
          /* already closed */
        }
      };

      const safeEnqueue = (chunk: string) => {
        if (closed) return;
        try {
          controller.enqueue(encoder.encode(chunk));
        } catch {
          // A client can disappear without delivering an abort event. An
          // enqueue failure is still terminal and must release the broker
          // subscription and keep-alive interval.
          cleanup();
        }
      };
      const send = (event: MonolithEvent) =>
        safeEnqueue(`data: ${JSON.stringify(event)}\n\n`);

      let replaying = true;
      let bufferedLive: MonolithEvent[] = [];
      const sendLive = (event: MonolithEvent) => {
        if (replaying) {
          bufferedLive.push(event);
        } else {
          send(event);
        }
      };
      unsubscribe = broker.subscribe(tenantId, sendLive);
      keepAlive = setInterval(() => safeEnqueue(`: keep-alive\n\n`), 15000);
      req.signal.addEventListener("abort", abort, { once: true });
      if (req.signal.aborted) {
        cleanup();
        return;
      }

      // Subscribe first, then replay the committed ledger. The client dedupes
      // by event_id, so an event committed during the query cannot be missed.
      // Hold live events until replay completes so the stream remains ordered
      // oldest-to-newest instead of interleaving new rows ahead of history.
      const replayedIds = new Set<string>();
      try {
        const history = await loadHistory(tenantId);
        for (const event of history.reverse()) {
          replayedIds.add(event.event_id);
          send(event);
        }
      } catch {
        safeEnqueue(`event: system\ndata: {"error":"history unavailable"}\n\n`);
      } finally {
        replaying = false;
        for (const event of bufferedLive) {
          if (!replayedIds.has(event.event_id)) send(event);
        }
        bufferedLive = [];
      }
    },
    cancel() {
      // ReadableStream cancellation already closes the controller.
      cleanup(false);
    },
  });
  return stream;
}
