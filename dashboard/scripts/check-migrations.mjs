import { readdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const scriptsDir = dirname(fileURLToPath(import.meta.url));
const migrationsDir =
  process.env.DATABASE_MIGRATIONS_DIR ??
  join(scriptsDir, "..", "..", "supabase", "migrations");

// Application migrations may create the deliberately unprivileged runtime
// role, but they must never mutate or remove cluster roles. Those operations
// require bootstrap-superuser credentials on Supabase Postgres.
const FORBIDDEN_ROLE_DDL = /^\s*(?:alter|drop)\s+(?:role|user)\b/im;

const files = (await readdir(migrationsDir))
  .filter((file) => file.endsWith(".sql"))
  .sort();

const violations = [];
for (const file of files) {
  const sql = await readFile(join(migrationsDir, file), "utf8");
  if (FORBIDDEN_ROLE_DDL.test(sql)) violations.push(file);
}

if (violations.length) {
  throw new Error(
    [
      "Privileged role DDL is not allowed in application migrations.",
      ...violations.map((file) => `- ${file}`),
      "Move role mutations to a bootstrap-superuser script.",
    ].join("\n"),
  );
}

console.log(`[migrations] Checked ${files.length} application migrations.`);
