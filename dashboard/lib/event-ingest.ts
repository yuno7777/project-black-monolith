// In-memory event broker: the dashboard's live fan-out.
//
// WHAT THIS FILE IS
// -----------------
// A tiny publish/subscribe bus inside one dashboard process. When an event is
// committed to Postgres, the LiveEventListener (live-event-listener.ts) loads
// it and calls broker.ingest(event); the broker fans it out to every SSE
// subscriber in the same tenant.
//
// WHAT IT IS *NOT* (know this for interviews)
// -------------------------------------------
// It is NOT the source of truth and NOT a message queue. The source of truth
// is Postgres:
//   - a newly connected client is replayed the persisted history BEFORE any
//     live events (see sse-event-stream.ts),
//   - this broker only fans out rows that were already committed.
// The comment says "No message queue, log tailing, or shared volume" — the
// modules POST their JSON to /api/ingest, Postgres stores it, and the broker
// is the live view over that store.
//
// WHY THE SINGLETON ON globalThis
// -------------------------------
// Next.js dev-mode hot-reloads can re-import modules; storing the broker on
// globalThis (instead of module scope) means one shared instance survives
// reloads instead of each reload creating a fresh broker that loses
// subscribers.
//
// WHO USES IT
// -----------
//   getBroker().subscribe()  <- sse-event-stream.ts (one subscriber per open
//                               browser connection)
//   getBroker().ingest()     <- live-event-listener.ts (Postgres NOTIFY)
//   getBroker()              <- /api/events route (via createEventStream)

import type { MonolithEvent } from "./types";

type Subscriber = (event: MonolithEvent) => void;

class EventBroker {
  // subscriber -> tenant id. Each SSE connection is one subscriber, tagged
  // with the tenant it may receive events for.
  private subscribers = new Map<Subscriber, string>();

  ingest(raw: MonolithEvent): MonolithEvent {
    // Push one committed event to every subscriber in its tenant. A broken
    // subscriber must never break ingestion (each call is wrapped in try).
    const event: MonolithEvent = {
      ...raw,
      received_ms: raw.received_ms ?? Date.now(),
    };

    for (const [sub, tenantId] of this.subscribers) {
      if (tenantId !== event.tenant_id) continue;
      try {
        sub(event);
      } catch {
        // A broken subscriber must never break ingestion.
      }
    }
    return event;
  }

  subscribe(tenantId: string, sub: Subscriber): () => void {
    // Register a subscriber for a tenant; returns an unsubscribe function the
    // SSE stream calls on cleanup.
    this.subscribers.set(sub, tenantId);
    return () => this.subscribers.delete(sub);
  }
}

const globalRef = globalThis as unknown as { __monolithBroker?: EventBroker };

export function getBroker(): EventBroker {
  if (!globalRef.__monolithBroker) {
    globalRef.__monolithBroker = new EventBroker();
  }
  return globalRef.__monolithBroker;
}
