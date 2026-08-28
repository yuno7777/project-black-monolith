// The checksum-verified migration runner.
//
// WHAT THIS FILE IS
// -----------------
// Applies supabase/migrations/*.sql to the `monolith` schema. It runs as a
// one-shot container (dashboard-migrator) BEFORE the dashboard starts, and
// also via the local runner. It connects as the ADMINISTRATIVE postgres role
// (the runtime role has no migration privileges — that separation is the
// point of the trust model).
//
// WHAT MAKES IT SAFE
// ------------------
//   1. Advisory lock (pg_try_advisory_lock): if two migrators race (e.g. two
//      replicas starting together), exactly one proceeds and the other fails
//      loudly instead of applying migrations twice.
//   2. Checksum tracking: every applied migration's SHA-256 is recorded in
//      monolith.schema_migrations. If a file that was ALREADY applied is
//      modified, startup fails ("Applied migration X was modified") — you
//      can't silently rewrite history; you add a NEW migration file instead.
//   3. Each migration runs in its own transaction: on failure it rolls back
//      and the process exits non-zero (Compose then refuses to start the
//      dashboard, and the failure is visible).
//
// The migration files themselves live in supabase/migrations/ and are shared
// with the docker-compose stack; the bootstrap role script
// (supabase/bootstrap/001-runtime-role.sh) creates the runtime login that the
// dashboard then uses.

import { readdir, readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import pg from "pg";

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  throw new Error("DATABASE_URL is required to start the dashboard.");
}

const migrationsDir = process.env.DATABASE_MIGRATIONS_DIR ?? "/app/supabase/migrations";
const MIGRATION_LOCK_ID = "7227014497148412001";
const { Client } = pg;
const client = new Client({ connectionString: databaseUrl });

await client.connect();
let migrationLockHeld = false;
try {
  const lock = await client.query(
    "select pg_try_advisory_lock($1::bigint) as acquired",
    [MIGRATION_LOCK_ID],
  );
  if (!lock.rows[0]?.acquired) {
    throw new Error("Another Project Black Monolith migrator is already running.");
  }
  migrationLockHeld = true;

  await client.query("create schema if not exists monolith");
  await client.query(`
    create table if not exists monolith.schema_migrations (
      version text primary key,
      checksum text,
      applied_at timestamptz not null default now()
    )
  `);
  await client.query(
    "alter table monolith.schema_migrations add column if not exists checksum text",
  );
  const files = (await readdir(migrationsDir))
    .filter((file) => file.endsWith(".sql"))
    .sort();

  for (const file of files) {
    const applied = await client.query(
      "select checksum from monolith.schema_migrations where version = $1",
      [file],
    );
    const sql = await readFile(join(migrationsDir, file), "utf8");
    const checksum = createHash("sha256").update(sql, "utf8").digest("hex");
    if (applied.rowCount) {
      // Already applied: verify it wasn't modified since (fail loudly if so),
      // and backfill the checksum for migrations applied before checksums
      // existed.
      const recorded = applied.rows[0].checksum;
      if (recorded && recorded !== checksum) {
        throw new Error(
          `Applied migration ${file} was modified (expected ${recorded}, found ${checksum}).`,
        );
      }
      if (!recorded) {
        await client.query(
          "update monolith.schema_migrations set checksum = $2 where version = $1 and checksum is null",
          [file, checksum],
        );
      }
      continue;
    }

    console.log(`[migrate] Applying ${file}`);
    await client.query("begin");
    try {
      await client.query(sql);
      await client.query(
        "insert into monolith.schema_migrations (version, checksum) values ($1, $2)",
        [file, checksum],
      );
      await client.query("commit");
      console.log(`[migrate] Applied ${file}`);
    } catch (error) {
      await client.query("rollback");
      const code =
        typeof error === "object" && error !== null && "code" in error
          ? ` (${String(error.code)})`
          : "";
      console.error(`[migrate] ${file} failed${code}`);
      throw error;
    }
  }
} finally {
  try {
    if (migrationLockHeld) {
      await client.query("select pg_advisory_unlock($1::bigint)", [MIGRATION_LOCK_ID]);
    }
  } finally {
    await client.end();
  }
}
