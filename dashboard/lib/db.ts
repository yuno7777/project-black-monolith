// The dashboard's PostgreSQL connection layer.
//
// WHAT THIS FILE IS
// -----------------
// The single place that owns the pg connection Pool and the two helpers every
// data-access module uses:
//   - getDb():      the shared Pool (one per process, cached on globalThis so
//                   Next.js dev hot-reloads don't leak connections).
//   - withTenantDb(tenantId, op): run `op` in a transaction with the
//                   tenant set as transaction-local context.
//   - withSessionDb(sessionHash, op): same, but scoped to an operator session
//                   digest instead of a tenant.
//
// THE LEAST-PRIVILEGE RUNTIME (the security-relevant part)
// --------------------------------------------------------
// The dashboard connects as `monolith_runtime` (a LOGIN role created by
// supabase/bootstrap/001-runtime-role.sh) and immediately `SET ROLE`s to
// `monolith_app` — a NOLOGIN group role that holds ONLY the SQL verbs the
// application needs (see the trust migration). The `options: "-c role=..."`
// on the Pool means EVERY connection sheds its administrative privileges
// before the app ever runs a query. Migrations run separately as the
// `postgres` role via scripts/migrate.mjs, so the runtime never has migration
// privileges.
//
// THE RLS CONTEXT (why the transaction matters)
// ---------------------------------------------
// `monolith.tenant_id` is set via set_config(..., true) — the "true" makes it
// TRANSACTION-LOCAL. Postgres row-level-security policies compare against this
// setting (see the trust migration), so:
//   - every query in this transaction can only see the tenant that was set;
//   - when the transaction ends (commit/rollback) the setting disappears, so
//     a pooled connection can never leak one request's tenant into the next.
// The application ALSO filters by tenant_id in every query it writes — two
// independent bounds on the same property.

import { Pool, type PoolClient } from "pg";

const globalRef = globalThis as unknown as { __monolithPool?: Pool };

export function getDb(): Pool {
  if (!globalRef.__monolithPool) {
    const connectionString = process.env.DATABASE_URL;
    if (!connectionString) {
      throw new Error("DATABASE_URL is not configured.");
    }
    const appRole = process.env.DATABASE_APP_ROLE ?? "monolith_app";
    if (!/^[a-z_][a-z0-9_]{0,62}$/i.test(appRole)) {
      throw new Error("DATABASE_APP_ROLE is not a valid Postgres role name.");
    }
    globalRef.__monolithPool = new Pool({
      connectionString,
      // The login connection applies migrations before the server starts. The
      // runtime pool immediately sheds those administrative privileges and
      // executes as the narrowly-granted NOLOGIN role from the trust migration.
      options: `-c role=${appRole}`,
      application_name: "project-black-monolith-dashboard",
      max: 8,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 2_000,
    });
  }
  return globalRef.__monolithPool;
}

async function withDatabaseContext<T>(
  settings: { tenantId?: string; sessionHash?: string },
  operation: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await getDb().connect();
  try {
    await client.query("begin");
    if (settings.tenantId !== undefined) {
      if (!settings.tenantId || settings.tenantId.length > 128) {
        throw new Error("tenant database context is invalid");
      }
      await client.query(
        "select set_config('monolith.tenant_id', $1, true)",
        [settings.tenantId],
      );
    }
    if (settings.sessionHash !== undefined) {
      if (!/^[0-9a-f]{64}$/.test(settings.sessionHash)) {
        throw new Error("session database context is invalid");
      }
      await client.query(
        "select set_config('monolith.session_hash', $1, true)",
        [settings.sessionHash],
      );
    }
    const result = await operation(client);
    await client.query("commit");
    return result;
  } catch (error) {
    await client.query("rollback");
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Execute one tenant-scoped unit of work. The context is transaction-local, so
 * a pooled connection cannot leak one request's tenant into the next request.
 *
 * Used by: event-store.ts, incident-store.ts, benchmark-store.ts,
 * operations-store.ts, operator-auth.ts (session creation) — i.e. every data
 * access module in the dashboard.
 */
export function withTenantDb<T>(
  tenantId: string,
  operation: (client: PoolClient) => Promise<T>,
): Promise<T> {
  return withDatabaseContext({ tenantId }, operation);
}

/** Scope an operator-session lookup/revocation to its opaque digest.
 * Used by: operator-auth.ts authenticateSession/revokeOperatorSession. */
export function withSessionDb<T>(
  sessionHash: string,
  operation: (client: PoolClient) => Promise<T>,
): Promise<T> {
  return withDatabaseContext({ sessionHash }, operation);
}
