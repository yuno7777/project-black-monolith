import { Pool } from "pg";

const globalRef = globalThis as unknown as { __monolithPool?: Pool };

export function getDb(): Pool {
  if (!globalRef.__monolithPool) {
    const connectionString = process.env.DATABASE_URL;
    if (!connectionString) {
      throw new Error("DATABASE_URL is not configured.");
    }
    globalRef.__monolithPool = new Pool({
      connectionString,
      max: 8,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 2_000,
    });
  }
  return globalRef.__monolithPool;
}
