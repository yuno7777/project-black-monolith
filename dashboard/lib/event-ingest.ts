// In-memory event broker: the dashboard's ingest backend.
//
// Integration choice (documented in the dashboard README): each of the three
// modules already emits the shared Monolith event JSON, so the lowest-effort
// reliable integration is for each module to also POST that JSON to this
// dashboard's /api/ingest endpoint. Persisted Postgres history is replayed by
// the SSE route; this broker fans newly committed rows out to connected
// clients in the same tenant without waiting for a separate DB round-trip.
//
// A single process-wide singleton is stored on globalThis so it survives
// Next.js dev hot-reloads and is shared across route handlers.

import type { MonolithEvent } from "./types";

type Subscriber = (event: MonolithEvent) => void;

const MAX_RECENT_EVENT_IDS = 4_096;

export class EventBroker {
  private subscribers = new Map<Subscriber, string>();
  private seenIds = new Set<string>();
  private seenOrder: string[] = [];

  private markSeen(eventId: string): boolean {
    if (!eventId) return false;
    if (this.seenIds.has(eventId)) return true;
    this.seenIds.add(eventId);
    this.seenOrder.push(eventId);
    if (this.seenOrder.length > MAX_RECENT_EVENT_IDS) {
      const oldest = this.seenOrder.shift();
      if (oldest) this.seenIds.delete(oldest);
    }
    return false;
  }

  hasSeen(eventId: string): boolean {
    return this.seenIds.has(eventId);
  }

  ingest(raw: MonolithEvent): MonolithEvent {
    const event: MonolithEvent = {
      ...raw,
      received_ms: raw.received_ms ?? Date.now(),
    };
    if (this.markSeen(event.event_id)) {
      return event;
    }

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

  publish(raw: MonolithEvent | MonolithEvent[]): MonolithEvent[] {
    const items = Array.isArray(raw) ? raw : [raw];
    return items.map((item) => this.ingest(item));
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

export function getEventBroker(): EventBroker {
  return getBroker();
}
