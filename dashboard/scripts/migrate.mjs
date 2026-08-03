import { readdir, readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
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
  await client.end();
}
