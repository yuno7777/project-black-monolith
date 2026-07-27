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

const REJECTED = [
  {},
  { module: "mcp-shield" },
  { event_type: "orphan_event" },
  "this-is-not-an-object-at-all",
  {
    event_id: "not-a-uuid",
    module: "mcp-shield",
    event_type: "bad_id",
  },
];

const PREFIX = `malformed_probe_${randomUUID()}`;
const NORMALIZED = [
  { severity: "not-a-real-severity", details: {} },
  { severity: "warning", details: null },
  { severity: "info", details: "should-not-be-a-string" },
  { severity: "critical", details: [1, 2, 3] },
  { severity: "info", timestamp_ms: "not-a-number", details: { nested: null } },
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
    fail(`normalizable optional fields returned HTTP ${accepted.status}, expected 201`);
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
      fail(`details was not normalized to an object on ${event.event_id}`);
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
      `  [OK] ${REJECTED.length} invalid envelopes rejected; ${events.size} optional-field cases normalized`,
    );
    console.log("\nMALFORMED-EVENT TEST PASSED");
  }
}

await main();
