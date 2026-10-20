import type { PoolClient } from "pg";
import { getDb } from "@/lib/db";
import { getBroker } from "@/lib/event-ingest";
import { findEventsByIds } from "@/lib/event-store";

const CHANNEL = "monolith_security_events";
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** How long to wait before reconnecting after the listener lost its connection. */
const RECONNECT_AFTER_DISCONNECT_MS = 1_000;
/** How long to wait before retrying a connection that never came up. */
const RECONNECT_AFTER_FAILURE_MS = 5_000;

export interface EventNotification {
  event_id: string;
  tenant_id: string;
}

export function parseEventNotification(payload: string | undefined): EventNotification | null {
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

export class LiveEventListener {
  private client?: PoolClient;
  private starting?: Promise<void>;
  private retry?: ReturnType<typeof setTimeout>;
  private pending = new Map<string, EventNotification>();
  private draining = false;

  /**
   * @param acquireClient How a database connection is obtained. Overridden in
   *   tests; production uses the shared pool.
   * @param reconnectDelayMs How long to wait before trying again. Overridden
   *   in tests; production uses the constants below.
   */
  constructor(
    private readonly acquireClient: () => Promise<PoolClient> = () => getDb().connect(),
    private readonly reconnectDelayMs?: number,
  ) {}

  ensureStarted(): Promise<void> {
    if (this.client) return Promise.resolve();
    if (!this.starting) {
      this.starting = this.connect().finally(() => {
        this.starting = undefined;
      });
    }
    return this.starting;
  }

  private async connect() {
    let client: PoolClient;
    try {
      client = await this.acquireClient();
    } catch (error) {
      // There was no connection to be had. The listener schedules its own
      // retry: a listener that stays down until the next client happens to
      // connect leaves the live view dead, and the client that asked for it
      // has already been told that live delivery is unavailable.
      console.error("live event database listener could not connect", error);
      this.scheduleReconnect(false);
      throw error;
    }
    client.on("notification", (message) => {
      if (message.channel !== CHANNEL) return;
      const notification = parseEventNotification(message.payload);
      if (notification) this.enqueue(notification);
    });
    client.on("error", (error) => {
      console.error("live event database listener disconnected", error);
      this.disconnect(client);
    });
    // A connection that ends without an error is still a disconnect.
    client.on("end", () => this.disconnect(client));
    try {
      await client.query(`listen ${CHANNEL}`);
      this.client = client;
    } catch (error) {
      client.release(true);
      // The LISTEN itself failed. The listener schedules its own retry for
      // the same reason as above: nobody is going to ask it to start again.
      console.error("live event database listener could not LISTEN", error);
      this.scheduleReconnect(false);
      throw error;
    }
  }

  private disconnect(client: PoolClient) {
    if (this.client !== client) return;
    this.client = undefined;
    client.release(true);
    this.scheduleReconnect(true);
  }

  /**
   * Try again, and keep trying, until the listener is up.
   *
   * @param afterDisconnect Whether the listener was up and lost its
   *   connection, which is worth retrying sooner than a connection that
   *   never succeeded.
   */
  private scheduleReconnect(afterDisconnect: boolean) {
    if (this.retry) clearTimeout(this.retry);
    const delay =
      this.reconnectDelayMs ??
      (afterDisconnect ? RECONNECT_AFTER_DISCONNECT_MS : RECONNECT_AFTER_FAILURE_MS);
    this.retry = setTimeout(() => {
      this.retry = undefined;
      void this.ensureStarted().catch((error) => {
        console.error("live event database listener reconnect failed", error);
        this.scheduleReconnect(false);
      });
    }, delay);
    this.retry.unref?.();
  }

  enqueue(notification: EventNotification) {
    if (getBroker().hasSeen(notification.event_id)) return;
    this.pending.set(`${notification.tenant_id}/${notification.event_id}`, notification);
    void this.drain();
  }

  async drain() {
    if (this.draining) return;
    this.draining = true;
    try {
      while (this.pending.size) {
        // Coalesce all currently queued notifications per tenant into a single
        // batched lookup so bursty ingest does not fan out N round-trips.
        const batchByTenant = new Map<string, string[]>();
        for (const [key, notification] of Array.from(this.pending.entries())) {
          this.pending.delete(key);
          if (getBroker().hasSeen(notification.event_id)) continue;
          const list = batchByTenant.get(notification.tenant_id) ?? [];
          list.push(notification.event_id);
          batchByTenant.set(notification.tenant_id, list);
        }
        for (const [tenantId, eventIds] of batchByTenant) {
          try {
            const events = await findEventsByIds(tenantId, eventIds);
            for (const event of events) {
              getBroker().ingest(event);
            }
          } catch (error) {
            console.error("failed to load notified security events", error);
          }
        }
      }
    } finally {
      this.draining = false;
    }
  }
}

const globalRef = globalThis as unknown as { __monolithLiveListener?: LiveEventListener };

export function ensureLiveEventListener(): Promise<void> {
  if (!globalRef.__monolithLiveListener) {
    globalRef.__monolithLiveListener = new LiveEventListener();
  }
  return globalRef.__monolithLiveListener.ensureStarted();
}
