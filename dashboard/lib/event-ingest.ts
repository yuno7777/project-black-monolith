// In-memory event broker: the dashboard's ingest backend.
//
// Integration choice (documented in the dashboard README): each of the three
// modules already emits the shared Monolith event JSON, so the lowest-effort
// reliable integration is for each module to also POST that JSON to this
// dashboard's /api/ingest endpoint. This broker holds a bounded ring buffer of
// recent events and fans new ones out to every connected SSE client. No
// message queue, no file tailing, no shared volume — just HTTP in, SSE out.
//
// A single process-wide singleton is stored on globalThis so it survives
// Next.js dev hot-reloads and is shared across route handlers.

import type { MonolithEvent } from "./types";

type Subscriber = (event: MonolithEvent) => void;

class EventBroker {
  private buffer: MonolithEvent[] = [];
  private subscribers = new Set<Subscriber>();
  private seq = 0;
  private readonly capacity = 500;

  ingest(raw: MonolithEvent): MonolithEvent {
    const event: MonolithEvent = {
      ...raw,
      seq: ++this.seq,
      received_ms: raw.received_ms ?? Date.now(),
    };

    this.buffer.push(event);
    if (this.buffer.length > this.capacity) {
      this.buffer.splice(0, this.buffer.length - this.capacity);
    }

    for (const sub of this.subscribers) {
      try {
        sub(event);
      } catch {
        // A broken subscriber must never break ingestion.
      }
    }
    return event;
  }

  recent(): MonolithEvent[] {
    return [...this.buffer];
  }

  subscribe(sub: Subscriber): () => void {
    this.subscribers.add(sub);
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
