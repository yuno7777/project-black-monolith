import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import pg from "pg";

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  throw new Error("DATABASE_URL is required to start the dashboard.");
}

const migrationsDir = process.env.DATABASE_MIGRATIONS_DIR ?? "/app/supabase/migrations";
const { Client } = pg;
const client = new Client({ connectionString: databaseUrl });

await client.connect();
try {
  await client.query("create schema if not exists monolith");
  await client.query(`
    create table if not exists monolith.schema_migrations (
      version text primary key,
      applied_at timestamptz not null default now()
    )
  `);
  const files = (await readdir(migrationsDir))
    .filter((file) => file.endsWith(".sql"))
    .sort();

  for (const file of files) {
    const applied = await client.query(
      "select 1 from monolith.schema_migrations where version = $1",
      [file],
    );
    if (applied.rowCount) continue;

    const sql = await readFile(join(migrationsDir, file), "utf8");
    await client.query("begin");
    try {
      await client.query(sql);
      await client.query(
        "insert into monolith.schema_migrations (version) values ($1)",
        [file],
      );
      await client.query("commit");
    } catch (error) {
      await client.query("rollback");
      throw error;
    }
  }
} finally {
  await client.end();
}
