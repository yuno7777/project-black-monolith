// Malformed / incomplete event ingest test (dependency-free, Node 18+).
//
// Sends a batch of malformed events into the dashboard's /api/ingest path and
// confirms the broker normalizes them so the frontend can never render
// "undefined" or crash: every event that comes back over /api/events must have
// a numeric timestamp, string module/event_type, a valid severity, and an
// object `details` — and no field anywhere serializes to the literal
// "undefined".
//
// Run against a running dashboard:  node test/malformed-event.test.mjs
// (BASE defaults to http://localhost:3000)

const BASE = process.env.BASE || "http://localhost:3000";

const MALFORMED = [
  {}, // completely empty
  { module: "mcp-shield" }, // missing event_type, severity, details
  { event_type: "orphan_event" }, // missing module
  { severity: "not-a-real-severity", module: "vector-anchor", event_type: "x" },
  { module: "trace-audit", event_type: "empty_details", details: {} },
  { module: "trace-audit", event_type: "null_details", details: null },
  { module: "x", event_type: "string_details", details: "should-not-be-a-string" },
  { module: "x", event_type: "array_details", details: [1, 2, 3] },
  { timestamp_ms: "not-a-number", module: "x", event_type: "bad_ts", details: {} },
  "this-is-not-an-object-at-all",
  { module: "x", event_type: "nested_null", details: { tool: null, hash: undefined } },
];

const VALID_SEVERITIES = new Set(["info", "warning", "critical"]);

function fail(msg) {
  console.error(`  [FAIL] ${msg}`);
  process.exitCode = 1;
}

async function readEvents(ms) {
  // Open the SSE stream, collect events for `ms`, then return them.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  const events = [];
  try {
    const res = await fetch(`${BASE}/api/events`, { signal: controller.signal });
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let idx;
      while ((idx = buf.indexOf("\n\n")) !== -1) {
        const frame = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        for (const line of frame.split("\n")) {
          if (line.startsWith("data: ")) {
            try {
              events.push(JSON.parse(line.slice(6)));
            } catch {
              /* ignore non-JSON keep-alive */
            }
          }
        }
      }
    }
  } catch {
    /* aborted by timeout — expected */
  } finally {
    clearTimeout(timer);
  }
  return events;
}

async function main() {
  console.log(`== Malformed-event ingest test against ${BASE} ==`);

  // 1. Health check.
  const health = await fetch(`${BASE}/api/ingest`).then((r) => r.ok).catch(() => false);
  if (!health) {
    console.error(`  [FAIL] dashboard not reachable at ${BASE} — start it first.`);
    process.exit(1);
  }

  // 2. Post the malformed batch (both singly and as an array).
  for (const evt of MALFORMED) {
    const res = await fetch(`${BASE}/api/ingest`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(evt),
    });
    if (!res.ok) fail(`ingest rejected a malformed event with HTTP ${res.status}`);
  }
  // Also an array in one POST.
  await fetch(`${BASE}/api/ingest`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(MALFORMED),
  });

  // 3. Read the events back and assert every one is well-formed.
  const events = await readEvents(1500);
  if (events.length === 0) fail("no events streamed back from /api/events");

  let checked = 0;
  for (const e of events) {
    checked++;
    if (typeof e.timestamp_ms !== "number" || !Number.isFinite(e.timestamp_ms))
      fail(`event has non-numeric timestamp_ms: ${JSON.stringify(e)}`);
    if (typeof e.module !== "string" || e.module.length === 0)
      fail(`event has invalid module: ${JSON.stringify(e)}`);
    if (typeof e.event_type !== "string" || e.event_type.length === 0)
      fail(`event has invalid event_type: ${JSON.stringify(e)}`);
    if (!VALID_SEVERITIES.has(e.severity))
      fail(`event has invalid severity "${e.severity}": ${JSON.stringify(e)}`);
    if (e.details === null || typeof e.details !== "object")
      fail(`event details is not an object: ${JSON.stringify(e)}`);
    if (JSON.stringify(e).includes("undefined"))
      fail(`event serializes with a literal "undefined": ${JSON.stringify(e)}`);
  }

  if (process.exitCode === 1) {
    console.error("\nMALFORMED-EVENT TEST FAILED");
  } else {
    console.log(`  [OK]   ${checked} streamed events all normalized (defaults applied, no undefined)`);
    console.log("\nMALFORMED-EVENT TEST PASSED");
  }
}

main();
