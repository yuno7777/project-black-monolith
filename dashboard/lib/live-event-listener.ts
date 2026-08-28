// The Postgres LISTEN/NOTIFY bridge: how every dashboard instance learns about
// newly committed events.
//
// WHAT THIS FILE IS
// -----------------
// A single long-lived database connection per dashboard process that runs
// `LISTEN monolith_security_events`. The migration
// (supabase/migrations/20260803091919_add_live_delivery_and_retention.sql)
// created a trigger that calls pg_notify('monolith_security_events', ...)
// after EVERY insert into security_events. When this connection receives a
// notification, the listener loads the FULL event by id and pushes it into
// the in-process broker (event-ingest.ts), which fans it out to SSE clients.
//
// WHY THIS DESIGN (multi-instance correctness)
// --------------------------------------------
// If the dashboard is scaled to several instances, each instance's in-process
// broker would only see events ingested THROUGH that instance. Postgres
// LISTEN/NOTIFY delivers the notification to EVERY connected instance, so all
// instances stay in sync — the live feed is the same on every instance,
// because the trigger fires on the shared database.
//
// The notification payload is deliberately tiny (event_id + tenant_id only) —
// LISTEN/NOTIFY payloads are limited and the full row is re-fetched via
// findEventById() (scoped to the tenant, so RLS applies).
//
// RECONNECTION HANDLING
// ---------------------
// If the connection drops, the client emits 'error'; the listener releases
// the broken client and retries connect() after 1s (and after 5s when idle),
// so a Postgres blip degrades live delivery but self-heals.
//
// WHO USES IT
// -----------
//   /api/events route calls ensureLiveEventListener() before opening SSE
//   streams — so the first browser connection starts the listener.

import type { PoolClient } from "pg";
import { getDb } from "@/lib/db";
import { getBroker } from "@/lib/event-ingest";
import { findEventById } from "@/lib/event-store";

const CHANNEL = "monolith_security_events";
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface EventNotification {
  event_id: string;
  tenant_id: string;
}

export function parseEventNotification(payload: string | undefined): EventNotification | null {
  // The trigger sends {"event_id": "...", "tenant_id": "..."}. Validate
  // strictly (the payload is untrusted DB-level input); return null for
  // anything malformed rather than forwarding garbage.
  if (!payload) return null;
  try {
    const value = JSON.parse(payload) as Record<string, unknown>;
    if (
      typeof value.event_id !== "string"
      || !UUID_PATTERN.test(value.event_id)
      || typeof value.tenant_id !== "string"
      || !value.tenant_id.trim()
      || value.tenant_id.length > 128
    ) {
      return null;
    }
    return { event_id: value.event_id, tenant_id: value.tenant_id.trim() };
  } catch {
    return null;
  }
}

class LiveEventListener {
  private client?: PoolClient;
  private starting?: Promise<void>; // dedupe concurrent ensureStarted() calls
  private retry?: ReturnType<typeof setTimeout>;
  private pending = new Map<string, EventNotification>(); // notification queue
  private draining = false;

  ensureStarted(): Promise<void> {
    // Connect once; if a connect is already in flight, return the same promise.
    if (this.client) return Promise.resolve();
    if (!this.starting) {
      this.starting = this.connect().finally(() => {
        this.starting = undefined;
      });
    }
    return this.starting;
  }

  private async connect() {
    const client = await getDb().connect();
    client.on("notification", (message) => {
      if (message.channel !== CHANNEL) return;
      const notification = parseEventNotification(message.payload);
      if (notification) this.enqueue(notification);
    });
    client.on("error", (error) => {
      console.error("live event database listener disconnected", error);
      this.disconnect(client);
    });
    try {
      await client.query(`listen ${CHANNEL}`);
      this.client = client;
    } catch (error) {
      client.release(true);
      throw error;
    }
  }

  private disconnect(client: PoolClient) {
    // The listening connection died: drop it and schedule a reconnect in 1s.
    if (this.client !== client) return;
    this.client = undefined;
    client.release(true);
    if (this.retry) clearTimeout(this.retry);
    this.retry = setTimeout(() => {
      this.retry = undefined;
      void this.ensureStarted().catch((error) => {
        console.error("live event database listener reconnect failed", error);
        this.disconnectIfIdle();
      });
    }, 1_000);
    this.retry.unref?.();
  }

  private disconnectIfIdle() {
    // Slower retry loop used when the listener is idle (no clients).
    if (this.client || this.retry) return;
    this.retry = setTimeout(() => {
      this.retry = undefined;
      void this.ensureStarted().catch((error) => {
        console.error("live event database listener reconnect failed", error);
        this.disconnectIfIdle();
      });
    }, 5_000);
    this.retry.unref?.();
  }

  private enqueue(notification: EventNotification) {
    // Notifications can arrive in bursts faster than the (async) drain keeps
    // up; buffer them in a Map keyed by tenant/event_id (dedupe) and kick the
    // drain.
    this.pending.set(`${notification.tenant_id}/${notification.event_id}`, notification);
    void this.drain();
  }

  private async drain() {
    // Serialize the work: load each notified event from the ledger (RLS-scoped
    // via withTenantDb inside findEventById) and hand it to the broker. A
    // failed load is logged and the notification is dropped — the SSE replay
    // will still deliver the event to any client that connects later, so
    // nothing is permanently lost.
    if (this.draining) return;
    this.draining = true;
    try {
      while (this.pending.size) {
        const [key, notification] = this.pending.entries().next().value!;
        this.pending.delete(key);
        try {
          const event = await findEventById(notification.tenant_id, notification.event_id);
          if (event) getBroker().ingest(event);
        } catch (error) {
          console.error("failed to load a notified security event", error);
        }
      }
    } finally {
      this.draining = false;
    }
  }
}

const globalRef = globalThis as unknown as { __monolithLiveListener?: LiveEventListener };

export function ensureLiveEventListener(): Promise<void> {
  // Process-wide singleton (survives Next.js hot-reloads). Called from the
  // /api/events route before any SSE stream is created.
  if (!globalRef.__monolithLiveListener) {
    globalRef.__monolithLiveListener = new LiveEventListener();
  }
  return globalRef.__monolithLiveListener.ensureStarted();
}
