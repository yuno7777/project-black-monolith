import assert from "node:assert/strict";
import test from "node:test";
import {
  EVENT_SOURCE_CLOSED,
  EVENT_SOURCE_CONNECTING,
  EventStreamClient,
  type EventSourceLike,
} from "../lib/event-stream-client";

/**
 * The live view must survive a dashboard that is not ready yet.
 *
 * A failed connection is the one case the browser will not retry: it fails
 * the source permanently and the operator is left looking at a dark page
 * until they reload by hand. These tests drive the wrapper with a stand-in
 * source, so the replacement that happens is the replacement the browser
 * would get.
 */

class FakeSource implements EventSourceLike {
  onopen: ((event: unknown) => void) | null = null;
  onerror: ((event: unknown) => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  readyState = EVENT_SOURCE_CONNECTING;
  closed = false;

  close() {
    this.closed = true;
  }
}

function waitUntil(predicate: () => boolean, timeoutMs = 2_000) {
  return new Promise<void>((resolve, reject) => {
    const deadline = Date.now() + timeoutMs;
    const tick = () => {
      if (predicate()) return resolve();
      if (Date.now() > deadline) {
        return reject(new Error("timed out waiting for the stream to come back"));
      }
      setTimeout(tick, 5);
    };
    tick();
  });
}

test("a source the browser gave up on is replaced", async () => {
  const sources: FakeSource[] = [];
  const client = new EventStreamClient({
    url: "/api/events",
    createSource: () => {
      const source = new FakeSource();
      sources.push(source);
      return source;
    },
    retryDelayMs: 5,
  });
  client.start();
  assert.equal(sources.length, 1);

  // The browser failed the connection: readyState CLOSED means it will not
  // come back on its own.
  sources[0].readyState = EVENT_SOURCE_CLOSED;
  sources[0].onerror?.(new Event("error"));

  await waitUntil(() => sources.length === 2);
  assert.equal(sources[0].closed, true, "the abandoned source is closed");
  client.stop();
});

test("a dropped connection is left to the browser to retry", async () => {
  const sources: FakeSource[] = [];
  const client = new EventStreamClient({
    url: "/api/events",
    createSource: () => {
      const source = new FakeSource();
      sources.push(source);
      return source;
    },
    retryDelayMs: 5,
  });
  client.start();

  // The browser is reconnecting by itself; replacing the source would race
  // that retry.
  sources[0].readyState = EVENT_SOURCE_CONNECTING;
  sources[0].onerror?.(new Event("error"));

  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(sources.length, 1);
  client.stop();
});

test("the stream does not come back after the caller stops it", async () => {
  const sources: FakeSource[] = [];
  const client = new EventStreamClient({
    url: "/api/events",
    createSource: () => {
      const source = new FakeSource();
      sources.push(source);
      return source;
    },
    retryDelayMs: 5,
  });
  client.start();
  client.stop();
  assert.equal(sources[0].closed, true);

  sources[0].readyState = EVENT_SOURCE_CLOSED;
  sources[0].onerror?.(new Event("error"));

  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(sources.length, 1);
});

test("the caller is told when the stream opens and when it fails", async () => {
  const sources: FakeSource[] = [];
  const opened: number[] = [];
  const failed: number[] = [];
  const messages: string[] = [];
  const client = new EventStreamClient({
    url: "/api/events",
    createSource: () => {
      const source = new FakeSource();
      sources.push(source);
      return source;
    },
    retryDelayMs: 5,
    onOpen: () => opened.push(1),
    onError: () => failed.push(1),
    onMessage: (data) => messages.push(data),
  });
  client.start();

  sources[0].onopen?.(new Event("open"));
  sources[0].onmessage?.({ data: "{\"event_id\":\"e-1\"}" });
  sources[0].onerror?.(new Event("error"));

  assert.equal(opened.length, 1);
  assert.equal(failed.length, 1);
  assert.deepEqual(messages, ["{\"event_id\":\"e-1\"}"]);
  client.stop();
});
