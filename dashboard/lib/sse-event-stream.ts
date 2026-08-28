// Server-Sent Events (SSE) stream construction — the "live feed" protocol.
//
// WHAT THIS FILE IS
// -----------------
// Builds the ReadableStream that backs GET /api/events. Each browser that
// opens the feed gets one of these streams. The stream does two things in the
// right order:
//   1. REPLAY: sends the last 500 committed events from Postgres (or, when
//      the browser reconnects with a Last-Event-ID header, only events AFTER
//      that cursor).
//   2. LIVE: then streams new events as they arrive, via the broker
//      subscription.
//
// THE NO-GAP TRICK (know this for interviews)
// -------------------------------------------
// The order is: SUBSCRIBE to the broker FIRST, THEN replay the ledger.
//   - Subscribe-before-replay: an event committed while the replay query runs
//     is (a) possibly in the query result AND (b) buffered from the broker.
//     The client dedupes by event_id, so nothing is missed and nothing
//     duplicates.
//   - Live events are BUFFERED until the replay finishes, so the stream stays
//     ordered oldest-to-newest instead of interleaving new rows ahead of
//     history.
//
// OTHER DETAILS
// -------------
//   - Every event is sent with an SSE `id:` line (the event_id), so a browser
//     that drops and reconnects can resume with Last-Event-ID.
//   - The send() function dedupes by event_id with a bounded 2048-entry set
//     (a just-committed live event can arrive before older replay frames).
//   - A keep-alive comment is emitted every 15s so proxies don't time the
//     connection out.
//   - The stream is tenant-scoped: the broker subscription is registered for
//     the authenticated operator's tenant, and the replay query filters by
//     tenant_id (with RLS as a second bound).
//
// WHO USES IT
// -----------
// /api/events route (app/api/events/route.ts) — authenticates, calls
// ensureLiveEventListener(), then returns new Response(createEventStream(...)).
// The browser side consumes it with an EventSource in app/page.tsx.

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
  loadHistory: (tenantId: string, afterEventId?: string) => Promise<MonolithEvent[]> =
    (id, cursor) => listRecentEvents(id, 500, cursor),
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

      // Cleanup: release the broker subscription, stop the keep-alive, drop
      // the abort listener, and close the controller. Idempotent.
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
      // Bounded dedupe: track which event_ids were already sent (the set is
      // capped at 2048 entries, oldest dropped first, so memory is bounded).
      const sentIds = new Set<string>();
      const sentOrder: string[] = [];
      const send = (event: MonolithEvent) => {
        if (sentIds.has(event.event_id)) return;
        sentIds.add(event.event_id);
        sentOrder.push(event.event_id);
        if (sentOrder.length > 2_048) {
          sentIds.delete(sentOrder.shift()!);
        }
        safeEnqueue(`id: ${event.event_id}\ndata: ${JSON.stringify(event)}\n\n`);
      };

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
      const lastEventId = req.headers.get("last-event-id")?.trim();
      try {
        const history = await loadHistory(tenantId, lastEventId || undefined);
        for (const event of history.reverse()) {
          send(event);
        }
      } catch {
        safeEnqueue(`event: system\ndata: {"error":"history unavailable"}\n\n`);
      } finally {
        replaying = false;
        for (const event of bufferedLive) {
          send(event);
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
