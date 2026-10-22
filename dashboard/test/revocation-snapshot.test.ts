// Contract tests for the bounded revocation snapshot: GET /api/sessions/revoked.
//
// The failure these cover is a fail-open one. The snapshot used to be the
// tenant's entire live revoked set, so once that set grew past the modules'
// 64 KiB read cap the body was cut short, failed to parse, and every module
// kept the set it already had — serving a session that had been revoked a
// moment ago. The documented design is that the revocation path fails closed.
//
// No database and no live stack: the snapshot is exercised through the
// in-memory ledger, and the query itself is checked against the SQL the
// dashboard actually sends.

import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { POST as ingestPost } from "../app/api/ingest/route";
import { GET as revokedGet } from "../app/api/sessions/revoked/route";
import { clearMemoryEvents } from "../lib/event-store";
import {
  clearMemoryRevocations,
  readRevocationSnapshot,
  restoreSession,
  REVOCATION_SNAPSHOT_MAX_BYTES,
  REVOCATION_SNAPSHOT_MAX_ENTRIES,
  REVOCATION_SNAPSHOT_SQL,
  revokeSession,
} from "../lib/incident-store";

const MODULE_TOKEN = "vector-anchor-snapshot-token-01";
const TENANT = "tenant-snapshot";

/**
 * The cap every module reads the snapshot body with.
 *
 * A body that reaches it is cut short, and a cut-short body does not parse.
 * The response therefore has to stay strictly below it, for every tenant and
 * every identifier the tenant's agents choose.
 */
const MODULE_READ_CAP_BYTES = 64 * 1024;

/**
 * Run a body with environment variables set, then put them back.
 *
 * The routes read process.env at call time, so without this a test would
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

function snapshotEnv(): Record<string, string | undefined> {
  return {
    DATABASE_URL: undefined,
    EVENT_INGEST_TOKENS_JSON: JSON.stringify({
      [TENANT]: { "vector-anchor": MODULE_TOKEN },
    }),
  };
}

/** Ask the snapshot endpoint for the tenant's live revoked set. */
async function fetchSnapshot(): Promise<{ status: number; body: string; json: any }> {
  const response = await revokedGet(
    new Request("http://localhost/api/sessions/revoked", {
      headers: {
        authorization: `Bearer ${MODULE_TOKEN}`,
        "x-monolith-tenant-id": TENANT,
        "x-monolith-module": "vector-anchor",
      },
    }),
  );
  const body = await response.text();
  return { status: response.status, body, json: JSON.parse(body) };
}

/** File one event as the module would, and read the dashboard's answer. */
async function ingestOne(): Promise<{ status: number; json: any }> {
  const response = await ingestPost(
    new Request("http://localhost/api/ingest", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${MODULE_TOKEN}`,
      },
      body: JSON.stringify([
        {
          module: "vector-anchor",
          // The id is the module's and the ledger's idempotency key, so it
          // carries one of its own, exactly as a module's emitter does.
          event_id: randomUUID(),
          event_type: "retrieval",
          severity: "info",
          tenant_id: TENANT,
        },
      ]),
    }),
  );
  return { status: response.status, json: await response.json() };
}

/** A session id of the longest length the ledger's schema allows. */
function longSessionId(index: number, length = 128): string {
  const prefix = `fill-${String(index).padStart(6, "0")}-`;
  return prefix + "s".repeat(length - prefix.length);
}

/** A session id that JSON escaping makes six times longer than it is. */
function quotedSessionId(index: number, length = 128): string {
  const prefix = `q-${String(index).padStart(6, "0")}-`;
  return prefix + '"'.repeat(length - prefix.length);
}

test("the snapshot query is bounded", () => {
  // The unbounded query was the defect: it returned the tenant's whole live
  // revoked set, and the body grew past the reader's cap.
  assert.match(REVOCATION_SNAPSHOT_SQL, /limit\s+\$2/i);
  assert.match(REVOCATION_SNAPSHOT_SQL, /restored_at is null/i);
  assert.match(REVOCATION_SNAPSHOT_SQL, /order by revoked_at desc/i);
  // The revision is read in the same statement, so the number and the rows
  // describe the same instant.
  assert.match(REVOCATION_SNAPSHOT_SQL, /revocation_revision\(\)/i);
});

test("the snapshot is complete at the cap and incomplete one entry past it", async () => {
  await withEnv(snapshotEnv(), async () => {
    clearMemoryRevocations();
    for (let i = 0; i < REVOCATION_SNAPSHOT_MAX_ENTRIES; i++) {
      await revokeSession(TENANT, "agent-cap", `cap-${i}`, "test", "test");
    }
    const atCap = await readRevocationSnapshot(TENANT);
    assert.equal(atCap.complete, true);
    assert.equal(atCap.truncated, false);
    assert.equal(atCap.revoked_sessions.length, REVOCATION_SNAPSHOT_MAX_ENTRIES);

    await revokeSession(TENANT, "agent-cap", "cap-overflow", "test", "test");
    const overCap = await readRevocationSnapshot(TENANT);
    assert.equal(overCap.complete, false);
    assert.equal(overCap.truncated, true);
    // One entry past the cap is exactly what the extra row the query asks
    // for is there to detect.
    assert.equal(overCap.revoked_sessions.length, REVOCATION_SNAPSHOT_MAX_ENTRIES);
    clearMemoryRevocations();
  });
});

test("a tenant with 5,000 live revocations still answers under the read cap", async () => {
  await withEnv(snapshotEnv(), async () => {
    clearMemoryRevocations();
    // The longest identifiers the schema allows, so the body is as big as it
    // can get for the number of entries it carries.
    for (let i = 0; i < 5_000; i++) {
      await revokeSession(TENANT, "agent-flood", longSessionId(i), "test", "test");
    }

    const snapshot = await fetchSnapshot();
    assert.equal(snapshot.status, 200);
    const size = Buffer.byteLength(snapshot.body, "utf8");
    assert.ok(
      size < MODULE_READ_CAP_BYTES,
      `the snapshot is ${size} bytes, which the module's ${MODULE_READ_CAP_BYTES}-byte cap would cut short`,
    );
    assert.ok(size <= REVOCATION_SNAPSHOT_MAX_BYTES);
    assert.equal(snapshot.json.complete, false);
    assert.equal(snapshot.json.truncated, true);
    assert.equal(snapshot.json.revoked_sessions.length, REVOCATION_SNAPSHOT_MAX_ENTRIES);
    assert.equal(snapshot.json.revocations.length, REVOCATION_SNAPSHOT_MAX_ENTRIES);
    // The revision advanced: the tenant's live set changed, and the snapshot
    // says how far it has moved.
    assert.ok(snapshot.json.revision >= 5_000);
    clearMemoryRevocations();
  });
});

test("identifiers that JSON escaping inflates cannot push the body over the cap", async () => {
  await withEnv(snapshotEnv(), async () => {
    clearMemoryRevocations();
    for (let i = 0; i < 200; i++) {
      await revokeSession(TENANT, "agent-quotes", quotedSessionId(i), "test", "test");
    }
    const snapshot = await fetchSnapshot();
    assert.equal(snapshot.status, 200);
    const size = Buffer.byteLength(snapshot.body, "utf8");
    assert.ok(
      size < MODULE_READ_CAP_BYTES,
      `the snapshot is ${size} bytes, which the module's ${MODULE_READ_CAP_BYTES}-byte cap would cut short`,
    );
    // The body was bounded by measurement, not only by the row count, so the
    // module is told the set it received is not the whole set.
    assert.equal(snapshot.json.complete, false);
    assert.equal(snapshot.json.truncated, true);
    assert.ok(snapshot.json.revocations.length < REVOCATION_SNAPSHOT_MAX_ENTRIES);
    clearMemoryRevocations();
  });
});

test("a small tenant gets a complete snapshot with the agent id of each revocation", async () => {
  await withEnv(snapshotEnv(), async () => {
    clearMemoryRevocations();
    await revokeSession(TENANT, "agent-one", "session-a", "auto trip", "auto-circuit-breaker", [
      "mcp-shield",
      "vector-anchor",
    ]);
    await revokeSession(TENANT, "agent-two", "session-b", "manual", "analyst", ["trace-audit"]);

    const snapshot = await fetchSnapshot();
    assert.equal(snapshot.status, 200);
    assert.equal(snapshot.json.tenant_id, TENANT);
    assert.equal(typeof snapshot.json.generated_at_ms, "number");
    assert.equal(snapshot.json.complete, true);
    assert.equal(snapshot.json.truncated, false);
    assert.equal(snapshot.json.revision, 2);
    // Newest first: the session revoked last is the one the module has to
    // learn about soonest.
    assert.deepEqual(snapshot.json.revoked_sessions, ["session-b", "session-a"]);

    const revocations = snapshot.json.revocations as Array<{
      session_id: string;
      agent_id: string;
      revoked_at_ms: number;
    }>;
    assert.equal(revocations.length, 2);
    assert.equal(revocations[0].session_id, "session-b");
    // The ledger's revocation key is (tenant_id, agent_id, session_id), so
    // the session id alone does not identify a revocation.
    assert.equal(revocations[0].agent_id, "agent-two");
    assert.equal(revocations[1].agent_id, "agent-one");
    for (const entry of revocations) {
      assert.equal(typeof entry.revoked_at_ms, "number");
      assert.ok(entry.revoked_at_ms > 0);
    }
    clearMemoryRevocations();
  });
});

test("the revision advances when the live set changes and not when it does not", async () => {
  await withEnv(snapshotEnv(), async () => {
    clearMemoryRevocations();
    assert.equal((await readRevocationSnapshot(TENANT)).revision, 0);

    await revokeSession(TENANT, "agent-rev", "session-a", "test", "test");
    assert.equal((await readRevocationSnapshot(TENANT)).revision, 1);

    await revokeSession(TENANT, "agent-rev", "session-b", "test", "test");
    assert.equal((await readRevocationSnapshot(TENANT)).revision, 2);

    // A session that is already revoked is still revoked: the set did not
    // change, so a revision that moved here would stop being a change
    // detector.
    await revokeSession(TENANT, "agent-rev", "session-a", "test again", "test");
    assert.equal((await readRevocationSnapshot(TENANT)).revision, 2);

    // A restore takes the session out of the live set.
    await restoreSession(TENANT, "agent-rev", "session-a");
    assert.equal((await readRevocationSnapshot(TENANT)).revision, 3);
    assert.deepEqual(
      (await readRevocationSnapshot(TENANT)).revoked_sessions,
      ["session-b"],
    );

    // Restoring a session that is not revoked changes nothing.
    await restoreSession(TENANT, "agent-rev", "session-a");
    assert.equal((await readRevocationSnapshot(TENANT)).revision, 3);
    clearMemoryRevocations();
  });
});

test("the migration advances the revision from a trigger the runtime role cannot bypass", () => {  const sql = readFileSync(
    new URL(
      "../../supabase/migrations/20261021130000_add_revocation_revision.sql",
      import.meta.url,
    ),
    "utf8",
  );
  // A trigger, so that no code path — including one written later — can
  // forget to advance the revision.
  assert.match(sql, /create trigger revoked_sessions_revision[\s\S]*on monolith\.revoked_sessions/i);
  assert.match(sql, /after insert or update or delete on monolith\.revoked_sessions/i);
  // The function is security definer with an empty search path, so it cannot
  // be pointed at another schema's object.
  assert.match(sql, /create or replace function monolith\.bump_revocation_revision\(\)[\s\S]*?security definer[\s\S]*?set search_path = ''/i);
  assert.match(sql, /create or replace function monolith\.revocation_revision\(\)[\s\S]*?security definer[\s\S]*?set search_path = ''/i);
  // The counter is in the monolith schema, and the runtime role reaches it
  // only through the function.
  assert.match(sql, /create table if not exists monolith\.revocation_revisions/i);
  assert.match(sql, /revoke all on monolith\.revocation_revisions from[^;]*monolith_app/i);
  assert.match(sql, /grant execute on function monolith\.revocation_revision\(\) to monolith_app/i);
  // The revision is read from the tenant context, so a module cannot ask for
  // another tenant's revision by naming it.
  assert.match(sql, /current_setting\('monolith\.tenant_id', true\)/i);
});

test("the ingest response says whether its revoked list is the whole set", async () => {
  // The ingest answer is where a module learns the revoked set, and it is a
  // *bounded* list. Before this flag existed the module read the absence of
  // any statement as "this is everything", replaced its local set with the
  // bounded list, and dropped every revocation past the bound — so the
  // session revoked a moment ago was served again.
  await withEnv(snapshotEnv(), async () => {
    clearMemoryRevocations();
    clearMemoryEvents();

    // Under the cap the list is the whole set, and a module told so may
    // replace its local set with it.
    await revokeSession(TENANT, "agent-small", "session-small", "test", "test");
    const small = await ingestOne();
    assert.equal(small.status, 201);
    assert.equal(small.json.revoked_sessions_complete, true);
    assert.equal(small.json.revoked_sessions_truncated, false);
    assert.deepEqual(small.json.revoked_sessions, ["session-small"]);

    // One past the cap, the list is a part of the set.
    for (let i = 0; i < REVOCATION_SNAPSHOT_MAX_ENTRIES; i++) {
      await revokeSession(TENANT, "agent-big", `big-${i}`, "test", "test");
    }
    const big = await ingestOne();
    assert.equal(big.status, 201);
    assert.equal(big.json.revoked_sessions_complete, false);
    assert.equal(big.json.revoked_sessions_truncated, true);
    assert.equal(big.json.revoked_sessions.length, REVOCATION_SNAPSHOT_MAX_ENTRIES);
    clearMemoryRevocations();
    clearMemoryEvents();
  });
});

test("the ingest response cannot push the answer past the module's read cap", async () => {
  // The bound is on the body, not only on the number of entries: an
  // identifier is agent supplied and JSON escaping can make it six times
  // longer than it is. The body is measured before it is sent.
  await withEnv(snapshotEnv(), async () => {
    clearMemoryRevocations();
    clearMemoryEvents();
    for (let i = 0; i < 2_000; i++) {
      await revokeSession(TENANT, "agent-flood", quotedSessionId(i), "test", "test");
    }
    const answer = await ingestOne();
    assert.equal(answer.status, 201);
    const size = Buffer.byteLength(JSON.stringify(answer.json), "utf8");
    assert.ok(
      size < MODULE_READ_CAP_BYTES,
      `the ingest answer is ${size} bytes, which the module's ${MODULE_READ_CAP_BYTES}-byte cap would cut short`,
    );
    assert.equal(answer.json.revoked_sessions_complete, false);
    assert.equal(answer.json.revoked_sessions_truncated, true);
    clearMemoryRevocations();
    clearMemoryEvents();
  });
});
