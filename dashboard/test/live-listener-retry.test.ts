// The live event listener must recover from a database that is not ready.
//
// A failed LISTEN used to release the client and rethrow without scheduling
// the reconnect that the disconnect path uses, so a listener that had never
// connected stayed dead: the stream stayed open and silently stopped
// delivering events.
//
// No database and no live stack: the pooled client is a stand-in that fails
// its first LISTEN, and the ledger is the in-memory one, so the whole path —
// notification, lookup, publish — runs without Postgres.

import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import type { Pool } from "pg";
import { getBroker } from "../lib/event-ingest";
import { LiveEventListener } from "../lib/live-event-listener";
import { normalizeEvent, persistEvents } from "../lib/event-store";
import type { MonolithEvent } from "../lib/types";

const CHANNEL = "monolith_security_events";

/**
 * Run a body with environment variables set, then put them back.
 *
 * The ledger reads DATABASE_URL at call time, so without this a test would
 * inherit whatever the previous one left behind.
 */
async function withEnv(
  vars: Record<string, string | undefined>,
  body: () => void | Promise<void>,
): Promise<void> {
  const saved: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(vars)) {
    saved[key] = process.env[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  try {
    await body();
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

type Handler = (payload?: unknown) => void;

/**
 * A stand-in for a pooled client.
 *
 * `failListen` makes the LISTEN fail the way a database that is still
 * starting would, and the notification is delivered the way Postgres
 * delivers one: on the channel, with the event id and the tenant in the
 * payload.
 */
class FakeClient {
  readonly queries: string[] = [];
  released = false;
  listenSucceeded = false;
  private readonly handlers = new Map<string, Handler[]>();

  constructor(private readonly failListen: boolean) {}

  on(event: string, handler: Handler) {
    const handlers = this.handlers.get(event) ?? [];
    handlers.push(handler);
    this.handlers.set(event, handlers);
    return this;
  }

  async query(sql: string) {
    this.queries.push(sql);
    if (sql.trim().toLowerCase().startsWith("listen")) {
      if (this.failListen) throw new Error("the database is starting up");
      this.listenSucceeded = true;
    }
    return { rows: [] };
  }

  release(destroy?: boolean) {
    this.released = true;
    return destroy;
  }

  emit(event: string, payload?: unknown) {
    for (const handler of this.handlers.get(event) ?? []) handler(payload);
  }
}

/**
 * A stand-in for the pool, handing out a client per connect() call.
 *
 * With `failFirst` the first LISTEN fails and every later one succeeds,
 * which is the shape of a database that was not ready when the dashboard
 * asked for it.
 */
function fakePool(failFirst = true) {
  const clients: FakeClient[] = [];
  const pool = {
    async connect() {
      const client = new FakeClient(failFirst && clients.length === 0);
      clients.push(client);
      return client;
    },
  } as unknown as Pool;
  return { pool, clients };
}

/** Run a body with the stand-in pool in place of the real one. */
async function withFakePool(pool: Pool, body: () => void | Promise<void>): Promise<void> {
  const globalRef = globalThis as unknown as { __monolithPool?: Pool };
  const saved = globalRef.__monolithPool;
  globalRef.__monolithPool = pool;
  try {
    await body();
  } finally {
    if (saved === undefined) delete globalRef.__monolithPool;
    else globalRef.__monolithPool = saved;
  }
}

/**
 * Wait for a condition, polling on a timer.
 *
 * The timer keeps the event loop alive while the listener waits on its own
 * reconnect, which is an unref'd timer and would not do it on its own.
 */
async function waitFor(ready: () => boolean, timeoutMs = 10_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!ready()) {
    if (Date.now() > deadline) {
      throw new Error("timed out waiting for the listener to reconnect");
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

test("a listener that fails its first LISTEN reconnects and delivers a later event", async () => {
  await withEnv({ DATABASE_URL: undefined }, async () => {
    const tenantId = "tenant-retry";
    const eventId = randomUUID();
    // The event the notification will point at. It is committed before the
    // listener connects, the way a detection that landed while the database
    // was starting would be.
    await persistEvents([
      normalizeEvent({
        event_id: eventId,
        module: "mcp-shield",
        event_type: "schema_mismatch",
        severity: "critical",
        tenant_id: tenantId,
        timestamp_ms: 1_770_000_000_000,
      }),
    ]);

    const { pool, clients } = fakePool();
    await withFakePool(pool, async () => {
      const received: MonolithEvent[] = [];
      const unsubscribe = getBroker().subscribe(tenantId, (event) => received.push(event));
      try {
        const listener = new LiveEventListener();

        // The first LISTEN fails, so the caller is told the listener is not up.
        await assert.rejects(() => listener.ensureStarted(), /starting up/);
        assert.equal(received.length, 0, "nothing can be delivered before the listener is up");

        // Nobody asks the listener to try again: it must reconnect on its own.
        await waitFor(() => clients.length >= 2 && clients[1].listenSucceeded);

        // A notification that arrives after the reconnect carries the event.
        clients[1].emit("notification", {
          channel: CHANNEL,
          payload: JSON.stringify({ event_id: eventId, tenant_id: tenantId }),
        });
        await waitFor(() => received.length > 0);

        assert.equal(received[0].event_id, eventId);
        assert.equal(received[0].event_type, "schema_mismatch");
        assert.equal(received[0].tenant_id, tenantId);
      } finally {
        unsubscribe();
      }
    });
  });
});

test("a listener that connects is left on the connection it has", async () => {
  await withEnv({ DATABASE_URL: undefined }, async () => {
    const { pool, clients } = fakePool(false);
    await withFakePool(pool, async () => {
      const listener = new LiveEventListener();
      await listener.ensureStarted();

      assert.equal(clients.length, 1);
      assert.ok(clients[0].listenSucceeded);

      // A listener that is up schedules no reconnect of its own.
      await new Promise((resolve) => setTimeout(resolve, 1_500));
      assert.equal(clients.length, 1, "a working listener must not reconnect");
    });
  });
});

test("a failed connection is retried after a delay, not in a tight loop", async () => {
  await withEnv({ DATABASE_URL: undefined }, async () => {
    const { pool, clients } = fakePool();
    await withFakePool(pool, async () => {
      const listener = new LiveEventListener();
      await assert.rejects(() => listener.ensureStarted(), /starting up/);

      // The retry is scheduled, not immediate: a database that is slow to
      // start must not be asked once a second for the life of the process.
      await new Promise((resolve) => setTimeout(resolve, 300));
      assert.equal(clients.length, 1, "the listener must not retry immediately");

      await waitFor(() => clients.length >= 2 && clients[1].listenSucceeded);
    });
  });
});
