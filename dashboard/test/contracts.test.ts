import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  createEventStream,
  MAX_REPLAY_BUFFERED_EVENTS,
} from "../lib/sse-event-stream";
import { BenchmarkInputError, normalizeRun } from "../lib/benchmark-store";
import { decodeIncidentCursor, IncidentInputError } from "../lib/incident-store";
import { normalizeEvent } from "../lib/event-store";
import { authenticateIngest } from "../lib/ingest-auth";
import { authenticateOperatorToken, operatorCookie } from "../lib/operator-auth";
import { requireOperator } from "../lib/route-auth";
import { requireSameOrigin } from "../lib/route-auth";
import { JsonBodyError, readJsonBody } from "../lib/request-body";
import { parseEventNotification } from "../lib/live-event-listener";
import { operatorRateLimitKey } from "../lib/login-rate-limit";
import {
  authenticateExternalToken,
  ExternalAuthUnavailable,
  externalIdentityFromClaims,
} from "../lib/external-auth";
import { normalizeModuleLedgerHealth } from "../lib/operations-store";
import { alertConfigStatus } from "../lib/alert-config";
import { moduleStatsUrl } from "../app/api/operations/route";

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

test("operations health retains quiet defense layers", () => {
  const modules = normalizeModuleLedgerHealth([
    {
      module: "vector-anchor",
      events_24h: "7",
      critical_24h: "1",
      latest_ms: "1785700000000",
      policy_versions: ["frequency-anomaly@2"],
    },
  ]);
  assert.deepEqual(modules.map((module) => module.module), [
    "mcp-shield",
    "vector-anchor",
    "trace-audit",
  ]);
  assert.equal(modules[0].events_24h, 0);
  assert.equal(modules[1].critical_24h, 1);
  assert.equal(modules[2].latest_received_ms, null);
});

test("module health credentials only travel to trusted transports", () => {
  assert.equal(moduleStatsUrl("http://modules.example/stats", false), null);
  assert.equal(moduleStatsUrl("https://user:secret@modules.example/stats", false), null);
  assert.equal(moduleStatsUrl("https://modules.example/stats#fragment", false), null);
  assert.equal(
    moduleStatsUrl("http://127.0.0.1:8001/base", false)?.toString(),
    "http://127.0.0.1:8001/stats",
  );
  assert.equal(
    moduleStatsUrl("http://vector-anchor:8001", true)?.toString(),
    "http://vector-anchor:8001/stats",
  );
});

test("alert webhooks require a signed HTTPS destination", () => {
  assert.deepEqual(alertConfigStatus({}), { enabled: false });
  assert.equal(alertConfigStatus({ MONOLITH_ALERT_WEBHOOK_URL: "https://alerts.example.test" }).enabled, false);
  assert.equal(alertConfigStatus({
    MONOLITH_ALERT_WEBHOOK_URL: "http://alerts.example.test/hook",
    MONOLITH_ALERT_WEBHOOK_SECRET: "s".repeat(32),
  }).enabled, false);
  assert.equal(alertConfigStatus({
    MONOLITH_ALERT_WEBHOOK_URL: "https://alerts.example.test/hook",
    MONOLITH_ALERT_WEBHOOK_SECRET: "s".repeat(32),
  }).enabled, true);
  assert.equal(alertConfigStatus({
    MONOLITH_ALERT_WEBHOOK_URL: "http://127.0.0.1:8787/hook",
    MONOLITH_ALERT_WEBHOOK_SECRET: "s".repeat(32),
  }).enabled, true);
});

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
  assert.throws(
    () =>
      normalizeEvent({
        module: "mcp-shield",
        event_type: "probe",
        trace_id: "trace\nforged",
      }),
    /trace_id.*printable/,
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

test("configured bearer credentials must be bounded and header-safe", () => {
  process.env.OPERATOR_TOKENS_JSON = JSON.stringify({
    operator: "invalid token with spaces",
  });
  assert.throws(
    () => authenticateOperatorToken("valid-probe-token-000000"),
    /no usable operator/,
  );

  process.env.EVENT_INGEST_TOKENS_JSON = JSON.stringify({
    default: { "mcp-shield": "invalid token with spaces" },
  });
  assert.throws(
    () =>
      authenticateIngest(
        new Request("http://localhost/api/ingest"),
        "default",
        "mcp-shield",
      ),
    /no usable tenant/,
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
  process.env.OPERATOR_TRUST_PROXY_HEADERS = "false";
  const untrustedProxy = operatorCookie(
    new Request("http://dashboard/api/auth/session", {
      headers: { "x-forwarded-proto": "https" },
    }),
    "opaque",
    300,
  );
  process.env.OPERATOR_TRUST_PROXY_HEADERS = "true";
  const trustedProxy = operatorCookie(
    new Request("http://dashboard/api/auth/session", {
      headers: { "x-forwarded-proto": "https" },
    }),
    "opaque",
    300,
  );
  assert.doesNotMatch(local, /; Secure/);
  assert.doesNotMatch(untrustedProxy, /; Secure/);
  assert.match(trustedProxy, /; Secure/);
  assert.match(local, /HttpOnly; SameSite=Strict/);
});

test("browser mutations require a same-origin request", () => {
  assert.equal(
    requireSameOrigin(new Request("https://console.example/api/incidents", {
      method: "POST",
      headers: { origin: "https://console.example" },
    })),
    null,
  );
  assert.equal(
    requireSameOrigin(new Request("https://console.example/api/incidents", {
      method: "POST",
      headers: { origin: "https://attacker.example" },
    }))?.status,
    403,
  );
  assert.equal(
    requireSameOrigin(new Request("https://console.example/api/incidents", {
      method: "POST",
      headers: { "sec-fetch-site": "cross-site" },
    }))?.status,
    403,
  );
  assert.equal(
    requireSameOrigin(new Request("https://console.example/api/incidents", {
      method: "POST",
      headers: { authorization: "Bearer script-token" },
    })),
    null,
  );
});

test("dashboard responses declare a restrictive content security policy", () => {
  const config = readFileSync(new URL("../next.config.mjs", import.meta.url), "utf8");
  assert.match(config, /Content-Security-Policy/);
  assert.match(config, /default-src 'self'/);
  assert.match(config, /object-src 'none'/);
  assert.match(config, /frame-ancestors 'none'/);
  assert.match(config, /connect-src 'self'/);
  assert.doesNotMatch(config, /default-src \*/);
});

test("operator sessions throttle activity writes and clean expired rows", () => {
  const auth = readFileSync(new URL("../lib/operator-auth.ts", import.meta.url), "utf8");
  assert.match(auth, /last_seen_at < now\(\) - interval '5 minutes'/);
  assert.match(auth, /delete from monolith\.operator_sessions[\s\S]*expires_at <= now\(\)/);
  assert.doesNotMatch(auth, /update monolith\.operator_sessions\s+set last_seen_at = now\(\)\s+where session_hash/);
});

test("login rate-limit keys trust proxy headers only when explicitly enabled", () => {
  const req = new Request("https://console.example/api/auth/session", {
    method: "POST",
    headers: { "x-forwarded-for": "203.0.113.5, 10.0.0.1" },
  });
  process.env.OPERATOR_TRUST_PROXY_HEADERS = "false";
  const direct = operatorRateLimitKey(req);
  process.env.OPERATOR_TRUST_PROXY_HEADERS = "true";
  const proxied = operatorRateLimitKey(req);
  assert.match(direct, /^[0-9a-f]{64}$/);
  assert.match(proxied, /^[0-9a-f]{64}$/);
  assert.notEqual(direct, proxied);
});

test("external identities require explicit project role, tenant, and MFA", () => {
  process.env.OPERATOR_OIDC_REQUIRE_MFA = "true";
  assert.deepEqual(
    externalIdentityFromClaims({
      sub: "user-1",
      email: "analyst@example.com",
      aal: "aal2",
      app_metadata: {
        monolith_role: "analyst",
        monolith_tenant_id: "tenant-a",
      },
    }),
    {
      actor: "analyst@example.com",
      role: "analyst",
      tenant_id: "tenant-a",
      auth_type: "bearer",
    },
  );
  assert.equal(
    externalIdentityFromClaims({
      sub: "user-1",
      aal: "aal1",
      app_metadata: { monolith_role: "admin", monolith_tenant_id: "tenant-a" },
    }),
    null,
  );
  assert.equal(externalIdentityFromClaims({ sub: "user-1", aal: "aal2" }), null);
});

test("external identity metadata requires secure transport", async () => {
  process.env.OPERATOR_OIDC_ISSUER = "http://identity.example.test";
  process.env.OPERATOR_OIDC_AUDIENCE = "project-black-monolith";
  process.env.OPERATOR_OIDC_JWKS_URL = "http://identity.example.test/.well-known/jwks.json";
  await assert.rejects(
    () => authenticateExternalToken("not-a-jwt"),
    ExternalAuthUnavailable,
  );

  process.env.OPERATOR_OIDC_ISSUER = "http://127.0.0.1:54321";
  process.env.OPERATOR_OIDC_JWKS_URL = "http://127.0.0.1:54321/jwks.json";
  assert.equal(await authenticateExternalToken("not-a-jwt"), null);

  delete process.env.OPERATOR_OIDC_ISSUER;
  delete process.env.OPERATOR_OIDC_AUDIENCE;
  delete process.env.OPERATOR_OIDC_JWKS_URL;
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

test("event streams replay history before buffered live events without duplicates", async () => {
  let subscriber: ((event: ReturnType<typeof normalizeEvent>) => void) | undefined;
  let resolveHistory!: (events: ReturnType<typeof normalizeEvent>[]) => void;
  const historyPromise = new Promise<ReturnType<typeof normalizeEvent>[]>((resolve) => {
    resolveHistory = resolve;
  });
  const broker = {
    subscribe(
      _tenantId: string,
      callback: (event: ReturnType<typeof normalizeEvent>) => void,
    ) {
      subscriber = callback;
      return () => {};
    },
  };
  const event = (id: string, timestamp: number) =>
    normalizeEvent({
      event_id: id,
      module: "mcp-shield",
      event_type: "probe",
      timestamp_ms: timestamp,
    });
  const oldEvent = event("00000000-0000-4000-8000-000000000001", 1);
  const caughtUpEvent = event("00000000-0000-4000-8000-000000000002", 2);
  const liveEvent = event("00000000-0000-4000-8000-000000000003", 3);
  const stream = createEventStream(
    new Request("http://localhost/api/events"),
    "default",
    broker,
    async () => historyPromise,
  );
  const reader = stream.getReader();
  subscriber!(caughtUpEvent);
  subscriber!(liveEvent);
  resolveHistory([caughtUpEvent, oldEvent]);

  const decoder = new TextDecoder();
  const chunks = [];
  for (let index = 0; index < 3; index++) {
    const result = await reader.read();
    chunks.push(decoder.decode(result.value));
  }
  await reader.cancel();

  assert.match(chunks[0], new RegExp(oldEvent.event_id));
  assert.match(chunks[0], new RegExp(`id: ${oldEvent.event_id}`));
  assert.match(chunks[1], new RegExp(caughtUpEvent.event_id));
  assert.match(chunks[2], new RegExp(liveEvent.event_id));
  assert.equal(
    chunks.join("").match(new RegExp(`"event_id":"${caughtUpEvent.event_id}"`, "g"))?.length,
    1,
  );
});

test("event streams close and reconnect instead of buffering live events without bound", async () => {
  let subscriber: ((event: ReturnType<typeof normalizeEvent>) => void) | undefined;
  let unsubscribeCalls = 0;
  const stream = createEventStream(
    new Request("http://localhost/api/events"),
    "default",
    {
      subscribe(_tenantId, callback) {
        subscriber = callback;
        return () => { unsubscribeCalls++; };
      },
    },
    async () => new Promise<ReturnType<typeof normalizeEvent>[]>(() => {}),
  );
  const reader = stream.getReader();
  for (let index = 0; index <= MAX_REPLAY_BUFFERED_EVENTS; index++) {
    subscriber!(normalizeEvent({
      event_id: `00000000-0000-4000-8000-${index.toString().padStart(12, "0")}`,
      module: "mcp-shield",
      event_type: "probe",
    }));
  }

  const first = await reader.read();
  assert.match(new TextDecoder().decode(first.value), /reconnect/);
  assert.equal((await reader.read()).done, true);
  assert.equal(unsubscribeCalls, 1);
});

test("event streams pass Last-Event-ID to history replay", async () => {
  const cursor = "00000000-0000-4000-8000-000000000010";
  let observedCursor: string | undefined;
  const stream = createEventStream(
    new Request("http://localhost/api/events", {
      headers: { "Last-Event-ID": cursor },
    }),
    "tenant-a",
    { subscribe: () => () => {} },
    async (_tenant, afterEventId) => {
      observedCursor = afterEventId;
      return [];
    },
  );
  const reader = stream.getReader();
  await new Promise((resolve) => setTimeout(resolve, 0));
  await reader.cancel();
  assert.equal(observedCursor, cursor);
});

test("database event notifications reject malformed routing data", () => {
  assert.deepEqual(
    parseEventNotification(
      '{"event_id":"00000000-0000-4000-8000-000000000001","tenant_id":" tenant-a "}',
    ),
    {
      event_id: "00000000-0000-4000-8000-000000000001",
      tenant_id: "tenant-a",
    },
  );
  assert.equal(parseEventNotification(undefined), null);
  assert.equal(parseEventNotification("not-json"), null);
  assert.equal(parseEventNotification('{"event_id":"bad","tenant_id":"tenant-a"}'), null);
});

test("incident cursors are opaque, bounded, and strictly validated", () => {
  const encoded = Buffer.from(JSON.stringify({
    severity_rank: 1,
    received_ms: 1785715200000,
    event_id: "00000000-0000-4000-8000-000000000001",
  })).toString("base64url");
  assert.deepEqual(decodeIncidentCursor(encoded), {
    severity_rank: 1,
    received_ms: 1785715200000,
    event_id: "00000000-0000-4000-8000-000000000001",
  });
  assert.throws(() => decodeIncidentCursor("not-a-cursor"), IncidentInputError);
  const invalidRank = Buffer.from(JSON.stringify({
    severity_rank: 9,
    received_ms: 1,
    event_id: "00000000-0000-4000-8000-000000000001",
  })).toString("base64url");
  assert.throws(() => decodeIncidentCursor(invalidRank), /cursor is invalid/);
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

test("Compose separates migration authority from the dashboard runtime", () => {
  const compose = readFileSync(new URL("../../docker-compose.yml", import.meta.url), "utf8");
  const dockerfile = readFileSync(new URL("../Dockerfile", import.meta.url), "utf8");
  const bootstrap = readFileSync(
    new URL("../../supabase/bootstrap/001-runtime-role.sh", import.meta.url),
    "utf8",
  );

  assert.match(compose, /dashboard-migrator:[\s\S]*DATABASE_URL:\s+postgresql:\/\/postgres:/);
  assert.match(compose, /dashboard:[\s\S]*DATABASE_URL:\s+postgresql:\/\/monolith_runtime:/);
  assert.match(compose, /database-bootstrap:[\s\S]*PGHOST:\s+database/);
  assert.match(compose, /condition:\s+service_completed_successfully/);
  assert.match(compose, /x-service-hardening:[\s\S]*read_only:\s+true/);
  assert.match(compose, /no-new-privileges:true/);
  assert.equal(compose.match(/<<:\s+\*service-hardening/g)?.length, 7);
  assert.match(compose, /alert-dispatcher:[\s\S]*scripts\/dispatch-alerts\.mjs/);
  assert.doesNotMatch(dockerfile, /migrate\.mjs\s*&&\s*node server\.js/);
  assert.match(bootstrap, /create role monolith_runtime login password %L/i);
  assert.match(bootstrap, /alter role monolith_runtime with login password %L/i);
  assert.match(bootstrap, /nosuperuser nocreatedb nocreaterole noinherit noreplication nobypassrls/i);
  assert.match(bootstrap, /grant monolith_app to monolith_runtime/i);
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

test("circuit-breaker and retention migration fixes cascade delete, session delete RLS, and revoked_sessions", () => {
  const sql = readFileSync(
    new URL(
      "../../supabase/migrations/20260804120000_circuit_breaker_and_retention_fix.sql",
      import.meta.url,
    ),
    "utf8",
  );
  assert.match(sql, /create or replace function monolith\.forbid_incident_audit_mutation\(\)/i);
  assert.match(sql, /current_setting\('monolith\.retention_prune', true\) = 'on'/i);
  assert.match(sql, /set_config\('monolith\.retention_prune', 'on', true\)/i);
  assert.match(sql, /create policy monolith_app_operator_sessions_delete/i);
  assert.doesNotMatch(sql, /coalesce\(\s*nullif\(current_setting\('monolith\.tenant_id'/i);
  assert.match(sql, /create table if not exists monolith\.revoked_sessions/i);
  assert.match(sql, /alter table monolith\.revoked_sessions force row level security/i);
  assert.match(sql, /grant select, insert, update, delete on monolith\.revoked_sessions to monolith_app/i);
  assert.match(sql, /create policy monolith_app_revoked_sessions_tenant_isolation/i);
});

test("cross-layer session circuit breaker trips automatically on >= 2 modules and supports manual quarantine/restore", async () => {
  const {
    clearMemoryRevocations,
    listRevokedSessions,
    restoreSession,
    revokeSession,
  } = await import("../lib/incident-store");
  const { clearMemoryEvents } = await import("../lib/event-store");
  const { POST: ingestPost } = await import("../app/api/ingest/route");
  const {
    GET: sessionGet,
    POST: sessionPost,
    DELETE: sessionDelete,
  } = await import("../app/api/incidents/[eventId]/session/route");

  delete process.env.DATABASE_URL;
  clearMemoryEvents();
  clearMemoryRevocations();

  process.env.EVENT_INGEST_TOKENS_JSON = JSON.stringify({
    "tenant-cb": {
      "mcp-shield": "mcp-shield-secret-token-0001",
      "vector-anchor": "vector-anchor-secret-token-0002",
      "trace-audit": "trace-audit-secret-token-0003",
    },
  });
  process.env.OPERATOR_TOKENS_JSON = JSON.stringify({
    analyst: { token: "analyst-secret-token-0001", role: "analyst", tenant_id: "tenant-cb" },
    viewer: { token: "viewer-secret-token-00001", role: "viewer", tenant_id: "tenant-cb" },
  });

  const event1Id = "10000000-0000-4000-8000-000000000001";
  const event2Id = "10000000-0000-4000-8000-000000000002";

  // 1st module hit (mcp-shield critical) — should not trip circuit breaker yet.
  const res1 = await ingestPost(
    new Request("http://localhost/api/ingest", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer mcp-shield-secret-token-0001",
      },
      body: JSON.stringify({
        event_id: event1Id,
        module: "mcp-shield",
        event_type: "tool_call_blocked",
        severity: "critical",
        tenant_id: "tenant-cb",
        agent_id: "agent-007",
        session_id: "sess-compromised",
      }),
    }),
  );
  assert.equal(res1.status, 201);
  const body1 = await res1.json();
  assert.equal(body1.accepted, 1);
  assert.deepEqual(body1.revoked_sessions, []);

  // 2nd distinct module hit (vector-anchor warning/critical) — trips auto-circuit-breaker!
  const res2 = await ingestPost(
    new Request("http://localhost/api/ingest", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer vector-anchor-secret-token-0002",
      },
      body: JSON.stringify({
        event_id: event2Id,
        module: "vector-anchor",
        event_type: "canary_triggered",
        severity: "critical",
        tenant_id: "tenant-cb",
        agent_id: "agent-007",
        session_id: "sess-compromised",
      }),
    }),
  );
  assert.equal(res2.status, 201);
  const body2 = await res2.json();
  assert.equal(body2.accepted, 1);
  assert.deepEqual(body2.revoked_sessions, ["sess-compromised"]);

  const listed = await listRevokedSessions("tenant-cb");
  assert.equal(listed.length, 1);
  assert.equal(listed[0].session_id, "sess-compromised");
  assert.equal(listed[0].triggered_by, "auto-circuit-breaker");
  assert.deepEqual(listed[0].layers, ["mcp-shield", "vector-anchor"]);

  // GET /api/incidents/[eventId]/session reflects revocation
  const getRes = await sessionGet(
    new Request(`http://localhost/api/incidents/${event1Id}/session`, {
      headers: { authorization: "Bearer viewer-secret-token-00001" },
    }),
    { params: Promise.resolve({ eventId: event1Id }) },
  );
  assert.equal(getRes.status, 200);
  const getJson = await getRes.json();
  assert.equal(getJson.session.revoked, true);
  assert.equal(getJson.session.revocation.triggered_by, "auto-circuit-breaker");

  // Viewer cannot restore session (403), analyst can restore session (DELETE)
  const viewerDelete = await sessionDelete(
    new Request(`http://localhost/api/incidents/${event1Id}/session`, {
      method: "DELETE",
      headers: { authorization: "Bearer viewer-secret-token-00001" },
    }),
    { params: Promise.resolve({ eventId: event1Id }) },
  );
  assert.equal(viewerDelete.status, 403);

  const analystDelete = await sessionDelete(
    new Request(`http://localhost/api/incidents/${event1Id}/session`, {
      method: "DELETE",
      headers: { authorization: "Bearer analyst-secret-token-0001" },
    }),
    { params: Promise.resolve({ eventId: event1Id }) },
  );
  assert.equal(analystDelete.status, 200);
  const restoredJson = await analystDelete.json();
  assert.equal(restoredJson.session.revoked, false);

  // Analyst can manually quarantine session (POST)
  const analystPost = await sessionPost(
    new Request(`http://localhost/api/incidents/${event1Id}/session`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer analyst-secret-token-0001",
      },
      body: JSON.stringify({ reason: "Confirmed exfiltration attempt" }),
    }),
    { params: Promise.resolve({ eventId: event1Id }) },
  );
  assert.equal(analystPost.status, 200);
  const quarantinedJson = await analystPost.json();
  assert.equal(quarantinedJson.session.revoked, true);
  assert.equal(quarantinedJson.session.revocation.reason, "Confirmed exfiltration attempt");
  assert.equal(quarantinedJson.session.revocation.triggered_by, "analyst");

  // Direct store helpers
  await revokeSession("tenant-cb", "agent-007", "sess-manual", "manual test", "analyst", ["trace-audit"]);
  assert.equal((await listRevokedSessions("tenant-cb")).length, 2);
  await restoreSession("tenant-cb", "agent-007", "sess-manual");
  assert.equal((await listRevokedSessions("tenant-cb")).length, 1);
});

test("circuit-breaker thresholds are configurable, clamped, and default to critical", async () => {
  const { circuitBreakerMinLayers, circuitBreakerSeverities } = await import(
    "../lib/incident-store"
  );
  const previousSeverity = process.env.MONOLITH_CIRCUIT_BREAKER_MIN_SEVERITY;
  const previousLayers = process.env.MONOLITH_CIRCUIT_BREAKER_MIN_LAYERS;
  try {
    delete process.env.MONOLITH_CIRCUIT_BREAKER_MIN_SEVERITY;
    delete process.env.MONOLITH_CIRCUIT_BREAKER_MIN_LAYERS;
    assert.deepEqual([...circuitBreakerSeverities()], ["critical"]);
    assert.equal(circuitBreakerMinLayers(), 2);

    process.env.MONOLITH_CIRCUIT_BREAKER_MIN_SEVERITY = " WARNING ";
    assert.deepEqual([...circuitBreakerSeverities()], ["warning", "critical"]);
    process.env.MONOLITH_CIRCUIT_BREAKER_MIN_SEVERITY = "info";
    assert.deepEqual([...circuitBreakerSeverities()], ["info", "warning", "critical"]);
    process.env.MONOLITH_CIRCUIT_BREAKER_MIN_SEVERITY = "high";
    assert.deepEqual([...circuitBreakerSeverities()], ["critical"]);

    process.env.MONOLITH_CIRCUIT_BREAKER_MIN_LAYERS = "1";
    assert.equal(circuitBreakerMinLayers(), 1);
    process.env.MONOLITH_CIRCUIT_BREAKER_MIN_LAYERS = "3";
    assert.equal(circuitBreakerMinLayers(), 3);
    for (const invalid of ["0", "4", "2.5", "many"]) {
      process.env.MONOLITH_CIRCUIT_BREAKER_MIN_LAYERS = invalid;
      assert.equal(circuitBreakerMinLayers(), 2, `layers ${invalid} must clamp to the default`);
    }
  } finally {
    if (previousSeverity === undefined) delete process.env.MONOLITH_CIRCUIT_BREAKER_MIN_SEVERITY;
    else process.env.MONOLITH_CIRCUIT_BREAKER_MIN_SEVERITY = previousSeverity;
    if (previousLayers === undefined) delete process.env.MONOLITH_CIRCUIT_BREAKER_MIN_LAYERS;
    else process.env.MONOLITH_CIRCUIT_BREAKER_MIN_LAYERS = previousLayers;
  }
});

test("circuit-breaker severity and layer thresholds gate the automatic trip", async () => {
  const { clearMemoryRevocations, listRevokedSessions } = await import("../lib/incident-store");
  const { POST: ingestPost } = await import("../app/api/ingest/route");

  delete process.env.DATABASE_URL;
  process.env.EVENT_INGEST_TOKENS_JSON = JSON.stringify({
    "tenant-thresh": {
      "mcp-shield": "mcp-shield-threshold-token-01",
      "vector-anchor": "vector-anchor-threshold-token-02",
      "trace-audit": "trace-audit-threshold-token-03",
    },
  });

  const ingest = async (module: string, token: string, eventId: string, severity: string) => {
    const res = await ingestPost(
      new Request("http://localhost/api/ingest", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          event_id: eventId,
          module,
          event_type: "threshold_probe",
          severity,
          tenant_id: "tenant-thresh",
          agent_id: "agent-threshold",
          session_id: "sess-threshold",
        }),
      }),
    );
    assert.equal(res.status, 201);
    return (await res.json()) as { revoked_sessions: string[] };
  };

  const tokens = {
    "mcp-shield": "mcp-shield-threshold-token-01",
    "vector-anchor": "vector-anchor-threshold-token-02",
    "trace-audit": "trace-audit-threshold-token-03",
  };
  const ids = (n: number, suffix: string) =>
    `${n}0000000-0000-4000-8000-${suffix.padStart(12, "0")}`;

  try {
    // Default: warnings do not count toward revocation.
    clearMemoryRevocations();
    delete process.env.MONOLITH_CIRCUIT_BREAKER_MIN_SEVERITY;
    delete process.env.MONOLITH_CIRCUIT_BREAKER_MIN_LAYERS;
    assert.deepEqual(
      (await ingest("mcp-shield", tokens["mcp-shield"], ids(1, "101"), "warning")).revoked_sessions,
      [],
    );
    assert.deepEqual(
      (await ingest("vector-anchor", tokens["vector-anchor"], ids(1, "102"), "warning"))
        .revoked_sessions,
      [],
      "two warning-severity layers must not trip the breaker by default",
    );
    assert.deepEqual(await listRevokedSessions("tenant-thresh"), []);

    // Opt-in: warnings count once the minimum severity is lowered.
    clearMemoryRevocations();
    process.env.MONOLITH_CIRCUIT_BREAKER_MIN_SEVERITY = "warning";
    (await ingest("mcp-shield", tokens["mcp-shield"], ids(2, "101"), "warning"));
    assert.deepEqual(
      (await ingest("vector-anchor", tokens["vector-anchor"], ids(2, "102"), "warning"))
        .revoked_sessions,
      ["sess-threshold"],
    );

    // Opt-in is per-run; the default layer requirement is still two, so a
    // third layer only matters when min-layers is raised.
    clearMemoryRevocations();
    delete process.env.MONOLITH_CIRCUIT_BREAKER_MIN_SEVERITY;
    process.env.MONOLITH_CIRCUIT_BREAKER_MIN_LAYERS = "3";
    assert.deepEqual(
      (await ingest("mcp-shield", tokens["mcp-shield"], ids(3, "101"), "critical"))
        .revoked_sessions,
      [],
    );
    assert.deepEqual(
      (await ingest("vector-anchor", tokens["vector-anchor"], ids(3, "102"), "critical"))
        .revoked_sessions,
      [],
      "two critical layers must not trip a three-layer requirement",
    );
    assert.deepEqual(
      (await ingest("trace-audit", tokens["trace-audit"], ids(3, "103"), "critical"))
        .revoked_sessions,
      ["sess-threshold"],
    );
    const listed = await listRevokedSessions("tenant-thresh");
    assert.deepEqual(listed[0].layers.slice().sort(), [
      "mcp-shield",
      "trace-audit",
      "vector-anchor",
    ]);
  } finally {
    delete process.env.MONOLITH_CIRCUIT_BREAKER_MIN_LAYERS;
    clearMemoryRevocations();
  }
});

test("session restore baseline migration keeps a restore watermark", () => {
  const sql = readFileSync(
    new URL(
      "../../supabase/migrations/20260805120000_session_restore_baseline.sql",
      import.meta.url,
    ),
    "utf8",
  );
  assert.match(sql, /add column if not exists restored_at timestamptz/i);
  assert.match(sql, /where restored_at is null/i);
});

test("an analyst restore settles the history that tripped the breaker", async () => {
  const { clearMemoryRevocations, listRevokedSessions, restoreSession } = await import(
    "../lib/incident-store"
  );
  const { POST: ingestPost } = await import("../app/api/ingest/route");

  delete process.env.DATABASE_URL;
  delete process.env.MONOLITH_CIRCUIT_BREAKER_MIN_SEVERITY;
  delete process.env.MONOLITH_CIRCUIT_BREAKER_MIN_LAYERS;
  clearMemoryRevocations();
  process.env.EVENT_INGEST_TOKENS_JSON = JSON.stringify({
    "tenant-restore": {
      "mcp-shield": "mcp-shield-restore-token-0001",
      "vector-anchor": "vector-anchor-restore-token-01",
      "trace-audit": "trace-audit-restore-token-001",
    },
  });

  const tokens: Record<string, string> = {
    "mcp-shield": "mcp-shield-restore-token-0001",
    "vector-anchor": "vector-anchor-restore-token-01",
    "trace-audit": "trace-audit-restore-token-001",
  };
  const ingest = async (module: string, eventType: string, severity: string) => {
    const res = await ingestPost(
      new Request("http://localhost/api/ingest", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${tokens[module]}`,
        },
        body: JSON.stringify({
          event_id: randomUUID(),
          module,
          event_type: eventType,
          severity,
          tenant_id: "tenant-restore",
          agent_id: "agent-restore",
          session_id: "sess-restore",
        }),
      }),
    );
    assert.equal(res.status, 201);
    return (await res.json()) as { revoked_sessions: string[] };
  };

  try {
    // Two critical layers trip the breaker, as usual.
    assert.deepEqual(
      (await ingest("mcp-shield", "tool_poisoning", "critical")).revoked_sessions,
      [],
    );
    assert.deepEqual(
      (await ingest("trace-audit", "divergence_breach", "critical")).revoked_sessions,
      ["sess-restore"],
    );

    assert.equal(await restoreSession("tenant-restore", "agent-restore", "sess-restore"), true);
    assert.deepEqual(await listRevokedSessions("tenant-restore"), []);
    // Keep the post-restore events unambiguous even on a coarse clock.
    await new Promise((resolve) => setTimeout(resolve, 5));

    // A refusal caused by the revocation is a consequence, not evidence: a
    // delayed delivery of it must not re-trip the restore.
    assert.deepEqual(
      (await ingest("vector-anchor", "session_quarantined", "critical")).revoked_sessions,
      [],
    );
    // One fresh layer is still not enough, now that the pre-restore history is
    // settled.
    assert.deepEqual(
      (await ingest("mcp-shield", "tool_poisoning", "critical")).revoked_sessions,
      [],
    );
    // Two fresh layers after the restore do trip it again.
    assert.deepEqual(
      (await ingest("trace-audit", "divergence_breach", "critical")).revoked_sessions,
      ["sess-restore"],
    );
  } finally {
    delete process.env.MONOLITH_CIRCUIT_BREAKER_MIN_SEVERITY;
    delete process.env.MONOLITH_CIRCUIT_BREAKER_MIN_LAYERS;
    clearMemoryRevocations();
  }
});

test("revocation snapshot endpoint serves module-scoped session ids over module credentials", async () => {
  const { clearMemoryRevocations, revokeSession } = await import("../lib/incident-store");
  const { GET: revokedGet } = await import("../app/api/sessions/revoked/route");

  delete process.env.DATABASE_URL;
  clearMemoryRevocations();
  process.env.EVENT_INGEST_TOKENS_JSON = JSON.stringify({
    "tenant-snap": {
      "mcp-shield": "mcp-shield-snapshot-token-0001",
      "vector-anchor": "vector-anchor-snapshot-token-01",
      "trace-audit": "trace-audit-snapshot-token-001",
    },
    "tenant-other": {
      "vector-anchor": "vector-anchor-other-token-0001",
    },
  });

  await revokeSession(
    "tenant-snap",
    "agent-snap",
    "sess-snap-a",
    "auto trip",
    "auto-circuit-breaker",
    ["mcp-shield", "vector-anchor"],
  );
  await revokeSession(
    "tenant-snap",
    "agent-snap",
    "sess-snap-b",
    "manual",
    "analyst",
    ["trace-audit"],
  );
  await revokeSession(
    "tenant-other",
    "agent-other",
    "sess-other",
    "auto trip",
    "auto-circuit-breaker",
    ["mcp-shield", "vector-anchor"],
  );

  const snapshot = await revokedGet(
    new Request("http://localhost/api/sessions/revoked", {
      headers: {
        authorization: "Bearer vector-anchor-snapshot-token-01",
        "x-monolith-tenant-id": "tenant-snap",
        "x-monolith-module": "vector-anchor",
      },
    }),
  );
  assert.equal(snapshot.status, 200);
  const body = await snapshot.json();
  assert.equal(body.tenant_id, "tenant-snap");
  assert.equal(typeof body.generated_at_ms, "number");
  assert.deepEqual(body.revoked_sessions.slice().sort(), ["sess-snap-a", "sess-snap-b"]);

  const deniedHeaderCases: Record<string, string>[] = [
    {},
    { "x-monolith-tenant-id": "tenant-snap", "x-monolith-module": "untrusted-layer" },
    {
      "x-monolith-tenant-id": "tenant-snap",
      "x-monolith-module": "vector-anchor",
      authorization: "Bearer vector-anchor-other-token-0001",
    },
    {
      "x-monolith-tenant-id": "tenant-other",
      "x-monolith-module": "vector-anchor",
      authorization: "Bearer vector-anchor-snapshot-token-01",
    },
  ];
  for (const headers of deniedHeaderCases) {
    const denied = await revokedGet(
      new Request("http://localhost/api/sessions/revoked", { headers }),
    );
    assert.equal(denied.status, 401);
  }

  clearMemoryRevocations();
  const empty = await revokedGet(
    new Request("http://localhost/api/sessions/revoked", {
      headers: {
        authorization: "Bearer vector-anchor-snapshot-token-01",
        "x-monolith-tenant-id": "tenant-snap",
        "x-monolith-module": "vector-anchor",
      },
    }),
  );
  assert.equal(empty.status, 200);
  assert.deepEqual((await empty.json()).revoked_sessions, []);
});

test("forensic evidence export computes canonical SHA-256 and HMAC-SHA256 signatures", async () => {
  const { exportIncidentEvidence } = await import("../lib/incident-store");
  const { GET: exportGet } = await import("../app/api/incidents/[eventId]/export/route");

  delete process.env.DATABASE_URL;
  process.env.OPERATOR_TOKENS_JSON = JSON.stringify({
    analyst: { token: "analyst-secret-token-0001", role: "analyst", tenant_id: "tenant-cb" },
  });
  const eventId = "10000000-0000-4000-8000-000000000001";

  // Unsigned (SHA-256 only) when no signing secret is configured
  delete process.env.MONOLITH_EVIDENCE_SIGNING_SECRET;
  delete process.env.MONOLITH_ALERT_WEBHOOK_SECRET;
  const unsignedBundle = await exportIncidentEvidence(eventId, "tenant-cb", "analyst");
  assert.ok(unsignedBundle);
  assert.equal(unsignedBundle.integrity.algorithm, "SHA-256");
  assert.match(unsignedBundle.integrity.canonical_sha256, /^[0-9a-f]{64}$/);
  assert.equal(unsignedBundle.integrity.signature, null);

  // Signed (HMAC-SHA256) when MONOLITH_EVIDENCE_SIGNING_SECRET >= 32 chars
  process.env.MONOLITH_EVIDENCE_SIGNING_SECRET = "e".repeat(32);
  const exportRes = await exportGet(
    new Request(`http://localhost/api/incidents/${eventId}/export`, {
      headers: { authorization: "Bearer analyst-secret-token-0001" },
    }),
    { params: Promise.resolve({ eventId }) },
  );
  assert.equal(exportRes.status, 200);
  const shaHeader = exportRes.headers.get("X-Monolith-Evidence-SHA256");
  const sigHeader = exportRes.headers.get("X-Monolith-Evidence-Signature");
  assert.ok(shaHeader && /^[0-9a-f]{64}$/.test(shaHeader));
  assert.ok(sigHeader && /^hmac-sha256=[0-9a-f]{64}$/.test(sigHeader));
  const exportedJson = await exportRes.json();
  assert.equal(exportedJson.integrity.algorithm, "HMAC-SHA256");
  assert.equal(exportedJson.integrity.canonical_sha256, shaHeader);
  assert.equal(`hmac-sha256=${exportedJson.integrity.signature}`, sigHeader);
  delete process.env.MONOLITH_EVIDENCE_SIGNING_SECRET;
});

test("operations store probes MCP_SHIELD_INTERNAL_URL and replays dead letters", async () => {
  const { probeModuleRuntimes, replayDeadLetters } = await import("../lib/operations-store");
  const opsSource = readFileSync(new URL("../lib/operations-store.ts", import.meta.url), "utf8");
  assert.doesNotMatch(opsSource, /Promise\.all\(\[\s*client\.query/);

  const originalFetch = globalThis.fetch;
  process.env.MCP_SHIELD_INTERNAL_URL = "http://127.0.0.1:8003";
  process.env.VECTOR_ANCHOR_INTERNAL_URL = "http://127.0.0.1:8001";
  process.env.TRACE_AUDIT_INTERNAL_URL = "http://127.0.0.1:8002";
  process.env.MONOLITH_MODULE_ADMIN_TOKEN = "admin-token-0000000000";

  const seenUrls: string[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = input.toString();
    seenUrls.push(`${init?.method ?? "GET"} ${url}`);
    if (url.endsWith("/stats")) {
      return new Response(
        JSON.stringify({
          outbox_pending: 4,
          outbox_dead_letter: 2,
          delivery: { pending: 4, dead: 2 },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    if (url.endsWith("/admin/replay-dead-letters")) {
      return new Response(JSON.stringify({ replayed: 2 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;

  try {
    const runtimes = await probeModuleRuntimes();
    const mcp = runtimes.find((r) => r.module === "mcp-shield");
    assert.ok(mcp);
    assert.equal(mcp.reachable, true);
    assert.equal(mcp.outbox_pending, 4);
    assert.equal(mcp.outbox_dead_letter, 2);

    const replay = await replayDeadLetters("tenant-cb");
    assert.equal(replay.total_replayed, 6);
    assert.ok(seenUrls.some((u) => u === "POST http://127.0.0.1:8003/admin/replay-dead-letters"));
  } finally {
    globalThis.fetch = originalFetch;
    delete process.env.MCP_SHIELD_INTERNAL_URL;
    delete process.env.VECTOR_ANCHOR_INTERNAL_URL;
    delete process.env.TRACE_AUDIT_INTERNAL_URL;
  }
});

test("login rate-limit uses last X-Forwarded-For hop and only counts failed login attempts", async () => {
  const { resetMemoryLoginRateLimits } = await import("../lib/login-rate-limit");
  const { POST: loginPost } = await import("../app/api/auth/session/route");

  delete process.env.DATABASE_URL;
  resetMemoryLoginRateLimits();

  process.env.OPERATOR_TRUST_PROXY_HEADERS = "true";
  const spoofA = operatorRateLimitKey(
    new Request("https://console.example/api/auth/session", {
      method: "POST",
      headers: { "x-forwarded-for": "198.51.100.1, 10.0.0.9" },
    }),
  );
  const spoofB = operatorRateLimitKey(
    new Request("https://console.example/api/auth/session", {
      method: "POST",
      headers: { "x-forwarded-for": "203.0.113.99, 10.0.0.9" },
    }),
  );
  assert.equal(spoofA, spoofB, "spoofing client-controlled first XFF hop must not change key");

  process.env.OPERATOR_TOKENS_JSON = JSON.stringify({
    admin: { token: "valid-operator-token-0001", role: "admin", tenant_id: "default" },
  });

  // 12 valid logins in a row must NEVER trigger 429 lockout
  for (let i = 0; i < 12; i++) {
    const res = await loginPost(
      new Request("http://localhost/api/auth/session", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          origin: "http://localhost",
          "x-forwarded-for": "10.0.0.50",
        },
        body: JSON.stringify({ token: "valid-operator-token-0001" }),
      }),
    );
    assert.equal(res.status, 200);
  }

  // 8 failed attempts return 401; 9th attempt is locked out with 429
  for (let i = 0; i < 8; i++) {
    const res = await loginPost(
      new Request("http://localhost/api/auth/session", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          origin: "http://localhost",
          "x-forwarded-for": "10.0.0.51",
        },
        body: JSON.stringify({ token: "wrong-operator-token-0001" }),
      }),
    );
    assert.equal(res.status, 401);
  }
  const lockedRes = await loginPost(
    new Request("http://localhost/api/auth/session", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "http://localhost",
        "x-forwarded-for": "10.0.0.51",
      },
      body: JSON.stringify({ token: "wrong-operator-token-0001" }),
    }),
  );
  assert.equal(lockedRes.status, 429);
});

test("proxy reads MONOLITH_DISABLE_AUTH dynamically at runtime and compose hardens long-running services", async () => {
  const { isAuthDisabled } = await import("../proxy");
  process.env.MONOLITH_DISABLE_AUTH = "false";
  assert.equal(isAuthDisabled(), false);
  process.env.MONOLITH_DISABLE_AUTH = "true";
  assert.equal(isAuthDisabled(), true);
  process.env.MONOLITH_DISABLE_AUTH = "false";

  const compose = readFileSync(new URL("../../docker-compose.yml", import.meta.url), "utf8");
  assert.match(compose, /MCP_SHIELD_STATUS_BIND:\s*"0\.0\.0\.0:8003"/);
  assert.match(compose, /MCP_SHIELD_INTERNAL_URL:\s*"?http:\/\/mcp-shield:8003"?/);
  assert.match(compose, /max-size:\s*"10m"/);
  assert.match(compose, /max-file:\s*"3"/);

  const dispatcher = readFileSync(
    new URL("../scripts/dispatch-alerts.mjs", import.meta.url),
    "utf8",
  );
  assert.match(dispatcher, /new Pool\(/);
  assert.match(dispatcher, /pool\.on\("error"/);
  assert.match(dispatcher, /prune_alert_deliveries/);
});

test("MONOLITH_DISABLE_AUTH is an exact-match opt-out in every auth helper", async () => {
  const { isAuthDisabled: proxyAuthDisabled } = await import("../proxy");
  const { isAuthDisabled: routeAuthDisabled } = await import("../lib/route-auth");

  // The escape hatch is documented as "the exact string true". A looser
  // comparison turns a value that means nothing on the secure path into one
  // that disables every operator check and grants every requester admin.
  for (const value of ["True", "TRUE", " true", "true ", "yes", "1", "false"]) {
    const env = { MONOLITH_DISABLE_AUTH: value } as NodeJS.ProcessEnv;
    assert.equal(proxyAuthDisabled(env), false, `proxy accepted ${JSON.stringify(value)}`);
    assert.equal(
      routeAuthDisabled(env),
      false,
      `route-auth accepted ${JSON.stringify(value)}`,
    );
  }

  assert.equal(
    proxyAuthDisabled({ MONOLITH_DISABLE_AUTH: "true" } as NodeJS.ProcessEnv),
    true,
  );
  assert.equal(
    routeAuthDisabled({ MONOLITH_DISABLE_AUTH: "true" } as NodeJS.ProcessEnv),
    true,
  );
  assert.equal(
    proxyAuthDisabled({} as NodeJS.ProcessEnv),
    false,
    "an unset variable must not disable authentication",
  );
});

