import assert from "node:assert/strict";
import test from "node:test";
import { EventEmitter } from "node:events";
import type { PoolClient } from "pg";
import { LiveEventListener } from "../lib/live-event-listener";

/**
 * The live listener must come up on its own.
 *
 * A listener that only starts when a client asks for it is a listener that
 * stays down for as long as nobody asks: the browser's EventSource gives up
 * on a failed connection and never asks again, so the operator's live view
 * would stay dark until somebody reloaded the page by hand.
 *
 * These tests drive the real listener with a stand-in database client, so
 * the reconnect the code schedules is the reconnect that happens.
 */

class FakeClient extends EventEmitter {
  released = false;
  listenError: Error | null = null;

  async query(sql: string) {
    if (sql.startsWith("listen") && this.listenError) throw this.listenError;
    return { rows: [] };
  }

  release(_destroy?: boolean) {
    this.released = true;
  }
}

function asClient(client: FakeClient): PoolClient {
  return client as unknown as PoolClient;
}

async function waitUntil(predicate: () => boolean, timeoutMs = 2_000) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) {
      throw new Error("timed out waiting for the listener to reconnect");
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

test("the listener retries after a connection it could not get", async () => {
  let attempts = 0;
  const listener = new LiveEventListener(
    async () => {
      attempts += 1;
      if (attempts === 1) throw new Error("the database is not ready yet");
      return asClient(new FakeClient());
    },
    5,
  );

  // The caller still learns that the listener is not up.
  await assert.rejects(() => listener.ensureStarted());

  // And the listener keeps trying by itself.
  await waitUntil(() => attempts >= 2);
  assert.equal(attempts, 2);
});

test("the listener retries after a LISTEN it could not issue", async () => {
  let attempts = 0;
  const clients: FakeClient[] = [];
  const listener = new LiveEventListener(
    async () => {
      attempts += 1;
      const client = new FakeClient();
      if (attempts === 1) client.listenError = new Error("the connection died mid-LISTEN");
      clients.push(client);
      return asClient(client);
    },
    5,
  );

  await assert.rejects(() => listener.ensureStarted());

  await waitUntil(() => attempts >= 2);
  assert.equal(clients.length, 2);
  assert.equal(clients[0].released, true, "the failed client is released");
});

test("the listener reconnects after the database drops the connection", async () => {
  let attempts = 0;
  const clients: FakeClient[] = [];
  const listener = new LiveEventListener(
    async () => {
      attempts += 1;
      const client = new FakeClient();
      clients.push(client);
      return asClient(client);
    },
    5,
  );

  await listener.ensureStarted();
  assert.equal(attempts, 1);

  clients[0].emit("error", new Error("connection terminated unexpectedly"));
  await waitUntil(() => attempts >= 2);
  assert.equal(clients[0].released, true);
});

test("a connection that ends without an error is still a disconnect", async () => {
  let attempts = 0;
  const clients: FakeClient[] = [];
  const listener = new LiveEventListener(
    async () => {
      attempts += 1;
      const client = new FakeClient();
      clients.push(client);
      return asClient(client);
    },
    5,
  );

  await listener.ensureStarted();
  clients[0].emit("end");
  await waitUntil(() => attempts >= 2);
});
