// In-memory event broker: the dashboard's ingest backend.
//
// Integration choice (documented in the dashboard README): each of the three
// modules already emits the shared Monolith event JSON, so the lowest-effort
// reliable integration is for each module to also POST that JSON to this
// dashboard's /api/ingest endpoint. Persisted Postgres history is replayed by
// the SSE route; this broker only fans newly committed rows out to connected
// clients in the same tenant. No message queue, log tailing, or shared volume.
//
// A single process-wide singleton is stored on globalThis so it survives
// Next.js dev hot-reloads and is shared across route handlers.

import type { MonolithEvent } from "./types";

type Subscriber = (event: MonolithEvent) => void;

class EventBroker {
  private subscribers = new Map<Subscriber, string>();

  ingest(raw: MonolithEvent): MonolithEvent {
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
