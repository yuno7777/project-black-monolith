// Authenticated malformed / incomplete event integration test (Node 18+).
//
// Required environment:
//   MONOLITH_EVENT_TOKEN_MCP_SHIELD
//   MONOLITH_OPERATOR_TOKEN
// Optional:
//   BASE=http://localhost:3000
//   MONOLITH_TENANT_ID=default

import { randomUUID } from "node:crypto";

const BASE = process.env.BASE || "http://localhost:3000";
const INGEST_TOKEN = process.env.MONOLITH_EVENT_TOKEN_MCP_SHIELD;
const OPERATOR_TOKEN = process.env.MONOLITH_OPERATOR_TOKEN;
const TENANT = process.env.MONOLITH_TENANT_ID || "default";

if (!INGEST_TOKEN || !OPERATOR_TOKEN) {
  console.error(
    "missing MONOLITH_EVENT_TOKEN_MCP_SHIELD or MONOLITH_OPERATOR_TOKEN; source .env first",
  );
  process.exit(1);
}

// Envelopes that must be rejected permanently (422), never retried.
//
// The optional-field cases below used to be asserted as *normalized* into safe
// values and accepted. That expectation predates 39f6998, which made envelope
// validation strict, and it was never updated -- which is why EVALUATION.md 5
// read NOT MEASURED: the stale test was not run against a live stack.
//
// Strict is the right contract for a security ledger. Coercing an unrecognised
// severity to "info" would silently downgrade a finding, and coercing a
// non-object `details` would discard the evidence a detection exists to carry.
// A permanent 422 dead-letters the event where a human can see it instead.
const REJECTED = [
  // --- required identity cannot be guessed --------------------------------
  {},
  { module: "mcp-shield" },
  { event_type: "orphan_event" },
  "this-is-not-an-object-at-all",
  {
    event_id: "not-a-uuid",
    module: "mcp-shield",
    event_type: "bad_id",
  },
  // --- optional fields, malformed: rejected rather than coerced -----------
  { module: "mcp-shield", event_type: "bad_severity", severity: "not-a-real-severity" },
  { module: "mcp-shield", event_type: "null_details", severity: "warning", details: null },
  { module: "mcp-shield", event_type: "string_details", severity: "info", details: "nope" },
  { module: "mcp-shield", event_type: "array_details", severity: "critical", details: [1, 2, 3] },
  { module: "mcp-shield", event_type: "bad_ts", severity: "info", timestamp_ms: "not-a-number" },
  { module: "mcp-shield", event_type: "bad_schema", schema_version: 99 },
];

const PREFIX = `malformed_probe_${randomUUID()}`;
// Valid envelopes exercising the fields that ARE optional: absent severity,
// absent timestamp, absent event_id. These must be accepted, defaulted
// server-side, and replayed to an authenticated subscriber under the right
// tenant -- the delivery half of the contract.
const NORMALIZED = [
  { severity: "warning", details: { note: "explicit severity" } },
  { details: { note: "severity defaults" } },
  { severity: "critical", details: {} },
  { severity: "info", details: { nested: { deep: true } } },
  { severity: "info", timestamp_ms: Date.now(), details: { note: "explicit ts" } },
].map((value, index) => ({
  module: "mcp-shield",
  event_type: `${PREFIX}_${index}`,
  tenant_id: TENANT,
  ...value,
}));

const VALID_SEVERITIES = new Set(["info", "warning", "critical"]);
let failures = 0;

function fail(message) {
  failures++;
  console.error(`  [FAIL] ${message}`);
}

function authorization(token) {
  return { Authorization: `Bearer ${token}` };
}

async function readEvents(expectedIds, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const events = new Map();
  try {
    const response = await fetch(`${BASE}/api/events`, {
      headers: authorization(OPERATOR_TOKEN),
      signal: controller.signal,
    });
    if (!response.ok || !response.body) {
      fail(`event stream returned HTTP ${response.status}`);
      return events;
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    while (events.size < expectedIds.size) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let frameEnd;
      while ((frameEnd = buffer.indexOf("\n\n")) !== -1) {
        const frame = buffer.slice(0, frameEnd);
        buffer = buffer.slice(frameEnd + 2);
        for (const line of frame.split("\n")) {
          if (!line.startsWith("data: ")) continue;
          const event = JSON.parse(line.slice(6));
          if (expectedIds.has(event.event_id)) events.set(event.event_id, event);
        }
      }
    }
  } catch (error) {
    if (error?.name !== "AbortError") fail(`event stream failed: ${error}`);
  } finally {
    clearTimeout(timer);
    // Release the stream on the SUCCESS path too. /api/events is an
    // open-ended SSE connection, so returning once every expected event has
    // arrived leaves the socket live, Node's event loop non-empty, and the
    // process hanging forever with its buffered stdout never flushed --
    // which reads as an inexplicably stuck test rather than a passing one.
    controller.abort();
  }
  return events;
}

async function ingest(body) {
  return fetch(`${BASE}/api/ingest`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...authorization(INGEST_TOKEN),
    },
    body: JSON.stringify(body),
  });
}

async function main() {
  console.log(`== Authenticated malformed-event test against ${BASE} ==`);

  const health = await fetch(`${BASE}/api/ingest`).then((r) => r.ok).catch(() => false);
  if (!health) {
    console.error(`  [FAIL] dashboard not reachable at ${BASE}`);
    process.exit(1);
  }

  for (const event of REJECTED) {
    const response = await ingest(event);
    if (response.status !== 422) {
      fail(`invalid required fields returned HTTP ${response.status}, expected 422`);
    }
  }

  const accepted = await ingest(NORMALIZED);
  if (accepted.status !== 201) {
    fail(`valid optional-field events returned HTTP ${accepted.status}, expected 201`);
  }
  const payload = await accepted.json();
  const ids = new Set(payload.event_ids ?? []);
  if (ids.size !== NORMALIZED.length) {
    fail(`ingest returned ${ids.size} event ids, expected ${NORMALIZED.length}`);
  }

  const events = await readEvents(ids, 2_000);
  if (events.size !== ids.size) {
    fail(`stream returned ${events.size} probe events, expected ${ids.size}`);
  }
  for (const event of events.values()) {
    if (event.tenant_id !== TENANT) fail(`wrong tenant on ${event.event_id}`);
    if (!VALID_SEVERITIES.has(event.severity)) fail(`invalid severity on ${event.event_id}`);
    if (!event.details || typeof event.details !== "object" || Array.isArray(event.details)) {
      fail(`details was not stored as an object on ${event.event_id}`);
    }
    if (!Number.isFinite(event.timestamp_ms)) fail(`invalid timestamp on ${event.event_id}`);
    if (JSON.stringify(event).includes("undefined")) {
      fail(`literal undefined serialized on ${event.event_id}`);
    }
  }

  if (failures) {
    console.error(`\nMALFORMED-EVENT TEST FAILED (${failures})`);
    process.exitCode = 1;
  } else {
    console.log(
      `  [OK] ${REJECTED.length} invalid envelopes rejected with 422; `
        + `${events.size} valid events accepted, defaulted and replayed`,
    );
    console.log("\nMALFORMED-EVENT TEST PASSED");
  }
}

await main();
