import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createEventStream } from "../lib/sse-event-stream";
import { BenchmarkInputError, normalizeRun } from "../lib/benchmark-store";
import { normalizeEvent } from "../lib/event-store";
import { authenticateIngest } from "../lib/ingest-auth";
import { authenticateOperatorToken, operatorCookie } from "../lib/operator-auth";
import { requireOperator } from "../lib/route-auth";
import { JsonBodyError, readJsonBody } from "../lib/request-body";

function detector(overrides: Record<string, unknown> = {}) {
  return {
    module: "vector-anchor",
    detector: "frequency_anomaly",
    paradigm: "threshold",
    benchmark_version: 2,
    confusion: { tp: 3, fp: 0, tn: 24, fn: 1 },
    latency_us: { p50: 10, p95: 20, p99: 30 },
    thresholds: {},
    ...overrides,
  };
}

test("benchmark normalization derives tenant and metrics server-side", () => {
  const run = normalizeRun({ detectors: [detector()] }, "tenant-a");
  assert.equal(run.tenant_id, "tenant-a");
  assert.equal(run.detectors[0].metrics.detection_rate, 0.75);
  assert.equal(run.detectors[0].benchmark_version, 2);
});

test("a bare detector array is accepted as one benchmark run", () => {
  const run = normalizeRun([detector()], "tenant-a");
  assert.equal(run.detectors.length, 1);
  assert.equal(run.detectors[0].detector, "frequency_anomaly");
});

test("event normalization requires identity-bearing contract fields", () => {
  assert.throws(() => normalizeEvent({}), /known module/);
  assert.throws(
    () => normalizeEvent({ module: "mcp-shield" }),
    /event_type is required/,
  );
  assert.throws(
    () => normalizeEvent({
      module: "mcp-shield",
      event_type: "probe",
      event_id: "not-a-uuid",
    }),
    /event_id must be a UUID/,
  );
  assert.throws(
    () =>
      normalizeEvent({
        module: "mcp-shield",
        event_type: "probe",
        event_id: "x".repeat(600),
      }),
    /event_id must be a UUID/,
  );
  assert.throws(
    () =>
      normalizeEvent({
        module: "mcp-shield",
        event_type: "probe",
        tenant_id: "x".repeat(129),
      }),
    /tenant_id/,
  );
});

test("event normalization applies safe defaults only when fields are absent", () => {
  const event = normalizeEvent({
    module: "trace-audit",
    event_type: "probe",
    tenant_id: " tenant-a ",
  });
  assert.equal(event.severity, "info");
  assert.deepEqual(event.details, {});
  assert.equal(event.tenant_id, "tenant-a");
  assert.equal(typeof event.timestamp_ms, "number");
});

test("event normalization rejects malformed ledger fields", () => {
  for (const input of [
    { severity: "unexpected" },
    { timestamp_ms: "not-a-number" },
    { timestamp_ms: 1e100 },
    { schema_version: 3 },
    { details: null },
    { source: "forged\nline" },
  ]) {
    assert.throws(() =>
      normalizeEvent({
        module: "trace-audit",
        event_type: "probe",
        ...input,
      }),
    );
  }
  assert.equal(
    normalizeEvent({
      module: "trace-audit",
      event_type: "probe",
      schema_version: 2,
      severity: "critical",
      details: { safe: true },
    }).severity,
    "critical",
  );
});

test("JSON body limits count UTF-8 bytes and chunked content", async () => {
  const multibyte = JSON.stringify({ value: "😀".repeat(10) });
  await assert.rejects(
    () =>
      readJsonBody(
        new Request("http://localhost/api", { method: "POST", body: multibyte }),
        30,
      ),
    (error: unknown) => error instanceof JsonBodyError && error.status === 413,
  );
  assert.deepEqual(
    await readJsonBody(
      new Request("http://localhost/api", {
        method: "POST",
        body: JSON.stringify({ safe: true }),
      }),
      64,
    ),
    { safe: true },
  );
});

test("benchmark latency is complete, non-negative, and ordered", () => {
  for (const latency of [
    { p50: "fast", p95: 20, p99: 30 },
    { p50: -1, p95: 20, p99: 30 },
    { p50: 20, p95: 10, p99: 30 },
    { p50: 10, p95: 20 },
  ]) {
    assert.throws(
      () => normalizeRun({ detectors: [detector({ latency_us: latency })] }, "tenant-a"),
      BenchmarkInputError,
    );
  }
});

test("duplicate detector rows and invalid versions are rejected before Postgres", () => {
  assert.throws(
    () => normalizeRun({ detectors: [detector(), detector()] }, "tenant-a"),
    /duplicate detector report/,
  );
  assert.throws(
    () => normalizeRun({ detectors: [detector({ benchmark_version: 32768 })] }, "tenant-a"),
    /benchmark_version/,
  );
  assert.throws(
    () =>
      normalizeRun(
        {
          detectors: [
            detector({
              confusion: { tp: 2_147_483_647, fp: 0, tn: 0, fn: 1 },
            }),
          ],
        },
        "tenant-a",
      ),
    /corpus totals/,
  );
  assert.throws(
    () => normalizeRun({ run_at_ms: -1, detectors: [detector()] }, "tenant-a"),
    /run_at_ms/,
  );
  assert.throws(
    () =>
      normalizeRun(
        { detectors: [detector({ detector: "x".repeat(65) })] },
        "tenant-a",
      ),
    /detector name/,
  );
});

test("operator credentials derive role and tenant from configuration", () => {
  process.env.OPERATOR_TOKENS_JSON = JSON.stringify({
    alice: { token: "alice-token-000000", role: "analyst", tenant_id: "tenant-a" },
  });
  assert.deepEqual(authenticateOperatorToken("alice-token-000000"), {
    actor: "alice",
    role: "analyst",
    tenant_id: "tenant-a",
    auth_type: "bearer",
  });
  assert.equal(authenticateOperatorToken("wrong-token-000000"), null);
});

test("legacy operator maps remain single-tenant admin credentials", () => {
  process.env.OPERATOR_TOKENS_JSON = JSON.stringify({
    operator: "legacy-token-000000",
  });
  const identity = authenticateOperatorToken("legacy-token-000000");
  assert.equal(identity?.role, "admin");
  assert.equal(identity?.tenant_id, "default");
});

test("credential reuse is rejected instead of creating ambiguous identity", () => {
  process.env.OPERATOR_TOKENS_JSON = JSON.stringify({
    alice: { token: "shared-token-000000", role: "analyst", tenant_id: "tenant-a" },
    bob: { token: "shared-token-000000", role: "viewer", tenant_id: "tenant-a" },
  });
  assert.throws(
    () => authenticateOperatorToken("shared-token-000000"),
    /must not reuse a token/,
  );

  process.env.EVENT_INGEST_TOKENS_JSON = JSON.stringify({
    "tenant-a": {
      "mcp-shield": "shared-module-token-000000",
      "trace-audit": "shared-module-token-000000",
    },
  });
  assert.throws(
    () =>
      authenticateIngest(
        new Request("http://localhost/api/ingest", {
          headers: { authorization: "Bearer shared-module-token-000000" },
        }),
        "tenant-a",
        "mcp-shield",
      ),
    /must not reuse a token/,
  );
});

test("role hierarchy denies viewer writes and admits analyst writes", async () => {
  process.env.OPERATOR_TOKENS_JSON = JSON.stringify({
    reader: { token: "reader-token-000000", role: "viewer", tenant_id: "tenant-a" },
    analyst: { token: "analyst-token-00000", role: "analyst", tenant_id: "tenant-a" },
  });
  const viewer = await requireOperator(
    new Request("http://localhost/api/incidents", {
      headers: { authorization: "Bearer reader-token-000000" },
    }),
    "analyst",
  );
  const analyst = await requireOperator(
    new Request("http://localhost/api/incidents", {
      headers: { authorization: "Bearer analyst-token-00000" },
    }),
    "analyst",
  );
  assert.ok(viewer instanceof Response);
  assert.equal(viewer.status, 403);
  assert.ok(!(analyst instanceof Response));
  if (!(analyst instanceof Response)) assert.equal(analyst.role, "analyst");
});

test("operator cookie security follows the actual request transport", () => {
  process.env.OPERATOR_COOKIE_SECURE = "";
  const local = operatorCookie(new Request("http://localhost/api/auth/session"), "opaque", 300);
  const proxied = operatorCookie(
    new Request("http://dashboard/api/auth/session", {
      headers: { "x-forwarded-proto": "https" },
    }),
    "opaque",
    300,
  );
  assert.doesNotMatch(local, /; Secure/);
  assert.match(proxied, /; Secure/);
  assert.match(local, /HttpOnly; SameSite=Strict/);
});

test("event streams release broker subscriptions when readers cancel", async () => {
  let subscriber: ((event: ReturnType<typeof normalizeEvent>) => void) | undefined;
  let unsubscribeCalls = 0;
  const broker = {
    subscribe(
      _tenantId: string,
      callback: (event: ReturnType<typeof normalizeEvent>) => void,
    ) {
      subscriber = callback;
      return () => {
        unsubscribeCalls++;
      };
    },
  };
  const stream = createEventStream(
    new Request("http://localhost/api/events"),
    "tenant-a",
    broker,
    async () => [],
  );
  const reader = stream.getReader();
  await reader.cancel();

  assert.equal(unsubscribeCalls, 1);
  assert.ok(subscriber, "the broker was subscribed before history replay");
});

test("trust-model migration keeps the runtime role least-privileged", () => {
  const sql = readFileSync(
    new URL("../../supabase/migrations/20260727091512_production_trust_model.sql", import.meta.url),
    "utf8",
  );
  const dbSource = readFileSync(new URL("../lib/db.ts", import.meta.url), "utf8");
  assert.match(
    sql,
    /create role monolith_app\s+nologin\s+nosuperuser\s+nocreatedb\s+nocreaterole\s+noinherit\s+noreplication\s+nobypassrls/i,
  );
  assert.doesNotMatch(sql, /^\s*(?:alter|drop)\s+(?:role|user)\b/im);
  assert.match(
    sql,
    /from pg_roles[\s\S]*rolcanlogin[\s\S]*rolsuper[\s\S]*rolbypassrls[\s\S]*raise exception/i,
  );
  assert.match(sql, /on monolith\.security_events\s+for select\s+to monolith_app/i);
  assert.match(sql, /on monolith\.security_events\s+for insert\s+to monolith_app/i);
  assert.doesNotMatch(sql, /grant\s+update\s+on\s+monolith\.security_events\s+to\s+monolith_app/i);
  assert.match(sql, /\(tenant_id, agent_id, session_id, received_at desc\)/i);
  assert.match(sql, /create table if not exists monolith\.operator_sessions/i);
  assert.match(sql, /current_setting\('monolith\.tenant_id', true\)/i);
  assert.match(sql, /current_setting\('monolith\.session_hash', true\)/i);
  assert.match(
    dbSource,
    /set_config\('monolith\.tenant_id', \$1, true\)/i,
  );
  assert.match(
    dbSource,
    /set_config\('monolith\.session_hash', \$1, true\)/i,
  );
});

test("migration policy rejects privileged role mutations", () => {
  const migrationsDir = mkdtempSync(join(tmpdir(), "monolith-migrations-"));
  try {
    writeFileSync(
      join(migrationsDir, "unsafe.sql"),
      "alter role monolith_app nosuperuser;\n",
      "utf8",
    );
    const result = spawnSync(
      process.execPath,
      [fileURLToPath(new URL("../scripts/check-migrations.mjs", import.meta.url))],
      {
        encoding: "utf8",
        env: { ...process.env, DATABASE_MIGRATIONS_DIR: migrationsDir },
      },
    );

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Privileged role DDL is not allowed/);
    assert.match(result.stderr, /unsafe\.sql/);
  } finally {
    rmSync(migrationsDir, { recursive: true, force: true });
  }
});
