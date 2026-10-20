import { createHash } from "node:crypto";
import { getDb } from "@/lib/db";

const WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILED_ATTEMPTS = 8;
/**
 * Upper bound on the in-memory failure counters.
 *
 * The key is derived from a client-influenced value when
 * `OPERATOR_TRUST_PROXY_HEADERS` is on, so every distinct source string
 * creates an entry. Without a bound, an unauthenticated caller could grow
 * the dashboard's heap without limit.
 */
const MAX_MEMORY_ENTRIES = 10_000;

type MemoryLimitEntry = {
  windowStarted: number;
  attempts: number;
};

const memoryRateLimitRef = globalThis as unknown as {
  __monolithLoginLimits?: Map<string, MemoryLimitEntry>;
};

function memoryLimits(): Map<string, MemoryLimitEntry> {
  if (!memoryRateLimitRef.__monolithLoginLimits) {
    memoryRateLimitRef.__monolithLoginLimits = new Map<string, MemoryLimitEntry>();
  }
  return memoryRateLimitRef.__monolithLoginLimits;
}

export function resetMemoryLoginRateLimits(): void {
  memoryLimits().clear();
}

export function operatorRateLimitKey(req: Request): string {
  let source = "direct-client";
  if (process.env.OPERATOR_TRUST_PROXY_HEADERS === "true") {
    const xff = req.headers.get("x-forwarded-for");
    const parts = xff
      ? xff.split(",").map((part) => part.trim()).filter(Boolean)
      : [];
    source = (parts.length > 0 ? parts[parts.length - 1] : undefined)
      || req.headers.get("x-real-ip")?.trim()
      || source;
  }
  return createHash("sha256").update(`operator-login:${source}`).digest("hex");
}

function getMemoryCount(key: string, now = Date.now()): number {
  const entry = memoryLimits().get(key);
  if (!entry) return 0;
  if (now - entry.windowStarted >= WINDOW_MS) {
    memoryLimits().delete(key);
    return 0;
  }
  return entry.attempts;
}

/**
 * Keep the in-memory counter table bounded.
 *
 * Expired entries are dropped first, because they carry no information. If
 * the table is still over the bound, the oldest entries are dropped: the
 * oldest counters are the ones closest to expiring anyway, and losing them
 * only means a source gets a fresh window rather than a permanent one.
 */
function enforceMemoryLimitBound(now = Date.now()): void {
  const limits = memoryLimits();
  if (limits.size <= MAX_MEMORY_ENTRIES) return;
  for (const [key, entry] of limits) {
    if (now - entry.windowStarted >= WINDOW_MS) limits.delete(key);
    if (limits.size <= MAX_MEMORY_ENTRIES) return;
  }
  const oldestFirst = [...limits.entries()].sort(
    (left, right) => left[1].windowStarted - right[1].windowStarted,
  );
  for (const [key] of oldestFirst) {
    limits.delete(key);
    if (limits.size <= MAX_MEMORY_ENTRIES) return;
  }
}

export async function checkOperatorLoginRateLimit(
  req: Request,
): Promise<{ allowed: boolean; key: string }> {
  const key = operatorRateLimitKey(req);
  const now = Date.now();
  const memAttempts = getMemoryCount(key, now);
  if (!process.env.DATABASE_URL) {
    return { allowed: memAttempts < MAX_FAILED_ATTEMPTS, key };
  }
  try {
    const result = await getDb().query<{ allowed: boolean }>(
      "select monolith.check_operator_login_allowed($1) as allowed",
      [key],
    );
    return {
      allowed: result.rows[0]?.allowed === true && memAttempts < MAX_FAILED_ATTEMPTS,
      key,
    };
  } catch (error) {
    // If the non-mutating check function is not yet migrated on an older DB,
    // fall back to the in-memory failure counter so sign-in can still proceed
    // while failed attempts continue to be recorded in Postgres.
    const code =
      typeof error === "object" && error !== null && "code" in error
        ? String((error as { code?: unknown }).code)
        : "";
    if (code === "42883") {
      return { allowed: memAttempts < MAX_FAILED_ATTEMPTS, key };
    }
    throw error;
  }
}

export async function recordOperatorLoginAttempt(
  req: Request,
): Promise<{ allowed: boolean; key: string }> {
  const key = operatorRateLimitKey(req);
  const now = Date.now();
  const existing = memoryLimits().get(key);
  const nextAttempts =
    !existing || now - existing.windowStarted >= WINDOW_MS
      ? 1
      : Math.min(1000, existing.attempts + 1);
  memoryLimits().set(key, {
    windowStarted:
      !existing || now - existing.windowStarted >= WINDOW_MS
        ? now
        : existing.windowStarted,
    attempts: nextAttempts,
  });
  enforceMemoryLimitBound(now);

  if (!process.env.DATABASE_URL) {
    return { allowed: nextAttempts <= MAX_FAILED_ATTEMPTS, key };
  }

  const result = await getDb().query<{ allowed: boolean }>(
    "select monolith.record_operator_login_attempt($1) as allowed",
    [key],
  );
  return { allowed: result.rows[0]?.allowed === true, key };
}

export async function clearOperatorLoginAttempts(key: string): Promise<void> {
  memoryLimits().delete(key);
  if (!process.env.DATABASE_URL) return;
  await getDb().query("select monolith.clear_operator_login_attempts($1)", [key]);
}
