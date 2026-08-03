#!/usr/bin/env node
import { createHmac } from "node:crypto";
import pg from "pg";

const databaseUrl = process.env.DATABASE_URL;
const targetValue = process.env.MONOLITH_ALERT_WEBHOOK_URL?.trim();
const secret = process.env.MONOLITH_ALERT_WEBHOOK_SECRET;
const tenants = (process.env.MONOLITH_ALERT_TENANTS ?? process.env.MONOLITH_TENANT_ID ?? "default")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);
const MAX_ATTEMPTS = 10;

if (!targetValue && !secret) {
  console.log("[alerts] webhook delivery is disabled");
  process.exit(0);
}
if (!databaseUrl) throw new Error("DATABASE_URL is required for alert delivery");
if (!targetValue || !secret || secret.length < 32 || secret.length > 512 || /[\r\n\0]/.test(secret)) {
  throw new Error("MONOLITH_ALERT_WEBHOOK_URL and a 32-512 character signing secret are required");
}
if (!tenants.length || tenants.some((tenant) => tenant.length > 128 || /[\r\n\0]/.test(tenant))) {
  throw new Error("MONOLITH_ALERT_TENANTS must contain bounded tenant identifiers");
}

const target = new URL(targetValue);
if (target.username || target.password || target.hash) {
  throw new Error("alert webhook URL must not contain credentials or a fragment");
}
if (target.protocol !== "https:" && !(target.protocol === "http:" && LOOPBACK.has(target.hostname))) {
  throw new Error("alert webhook URL must use HTTPS (HTTP is loopback-only)");
}

const { Client } = pg;
const client = new Client({
  connectionString: databaseUrl,
  options: "-c role=monolith_app",
  application_name: "project-black-monolith-alert-dispatcher",
});
let stopping = false;
process.on("SIGINT", () => { stopping = true; });
process.on("SIGTERM", () => { stopping = true; });

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function inTenant(tenant, operation) {
  await client.query("begin");
  try {
    await client.query("select set_config('monolith.tenant_id', $1, true)", [tenant]);
    const result = await operation();
    await client.query("commit");
    return result;
  } catch (error) {
    await client.query("rollback");
    throw error;
  }
}

async function claim(tenant) {
  return inTenant(tenant, async () => {
    const selected = await client.query(`
      select event_id::text, payload, attempts
        from monolith.alert_outbox
       where tenant_id = $1 and status = 'pending' and next_attempt_at <= now()
       order by next_attempt_at, created_at
       for update skip locked
       limit 1
    `, [tenant]);
    const alert = selected.rows[0];
    if (!alert) return null;
    await client.query(`
      update monolith.alert_outbox
         set attempts = attempts + 1,
             next_attempt_at = now() + interval '5 minutes',
             last_error = null
       where tenant_id = $1 and event_id = $2::uuid
    `, [tenant, alert.event_id]);
    return { ...alert, attempts: Number(alert.attempts) + 1 };
  });
}

async function markDelivered(tenant, eventId) {
  await inTenant(tenant, () => client.query(`
    update monolith.alert_outbox
       set status = 'delivered', delivered_at = now(), last_error = null
     where tenant_id = $1 and event_id = $2::uuid
  `, [tenant, eventId]));
}

async function markFailed(tenant, alert, message, permanent) {
  const dead = permanent || alert.attempts >= MAX_ATTEMPTS;
  const backoff = Math.min(300, 2 ** Math.min(alert.attempts, 8));
  await inTenant(tenant, () => client.query(`
    update monolith.alert_outbox
       set status = $3,
           next_attempt_at = now() + ($4::text || ' seconds')::interval,
           last_error = $5
     where tenant_id = $1 and event_id = $2::uuid
  `, [tenant, alert.event_id, dead ? "dead" : "pending", backoff, message.slice(0, 512)]));
}

async function deliver(tenant, alert) {
  const timestamp = Date.now().toString();
  const body = JSON.stringify({
    format: "project-black-monolith/critical-alert@1",
    sent_at_ms: Number(timestamp),
    tenant_id: tenant,
    event: alert.payload,
  });
  const signature = createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
  try {
    const response = await fetch(target, {
      method: "POST",
      redirect: "manual",
      signal: AbortSignal.timeout(10_000),
      headers: {
        "content-type": "application/json",
        "user-agent": "project-black-monolith-alerts/1",
        "x-monolith-event-id": alert.event_id,
        "x-monolith-timestamp": timestamp,
        "x-monolith-signature": `sha256=${signature}`,
      },
      body,
    });
    if (response.ok) {
      await markDelivered(tenant, alert.event_id);
      console.log(`[alerts] delivered ${alert.event_id}`);
      return;
    }
    const retryable = response.status === 408 || response.status === 429 || response.status >= 500;
    await markFailed(tenant, alert, `HTTP ${response.status}`, !retryable);
  } catch (error) {
    await markFailed(
      tenant,
      alert,
      error instanceof Error ? `${error.name}: ${error.message}` : "network request failed",
      false,
    );
  }
}

await client.connect();
console.log(`[alerts] dispatcher started for ${tenants.length} tenant(s)`);
try {
  while (!stopping) {
    let found = false;
    for (const tenant of tenants) {
      if (stopping) break;
      const alert = await claim(tenant);
      if (!alert) continue;
      found = true;
      await deliver(tenant, alert);
    }
    if (!found && !stopping) await delay(2_000);
  }
} finally {
  await client.end();
}
