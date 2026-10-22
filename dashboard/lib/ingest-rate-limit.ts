import { createHash } from "node:crypto";
import { getDb } from "@/lib/db";

/**
 * The window an ingest budget is spent in.
 *
 * Fixed, and short: the control exists so that one module cannot bury the
 * operator's view of the ledger, not so that a module is rationed for the
 * length of an incident. A minute of quiet restores the full budget.
 */
export const INGEST_RATE_LIMIT_WINDOW_MS = 60_000;
export const INGEST_RATE_LIMIT_WINDOW_SECONDS = 60;

/**
 * The number of events one module credential may file per window.
 *
 * Generous enough for a busy module and far below the point at which a flood
 * would hide a real detection: the dashboard renders the ledger as a live
 * stream, so a module that files thousands of events a minute is not merely
 * filling a table, it is pushing the attack out of the operator's screen.
 */
const DEFAULT_EVENT_BUDGET = 2_000;

/**
 * The largest budget the counter can represent.
 *
 * The counter's ceiling has to sit above the largest budget an operator can
 * configure. A ceiling below the budget would stop counting before the
 * budget was reached, and the limit would then never fire at all — the
 * control would be present in the code and absent in the defence.
 */
const MAX_EVENT_BUDGET = 1_000_000;

/**
 * Upper bound on the in-memory fallback counters.
 *
 * The key is a hash of a tenant and a module, both of which are fixed by the
 * credential configuration, so the table cannot grow the way a
 * client-influenced key could. It is bounded anyway: the fallback is the
 * path a dashboard without a database runs on, and a leak there would be a
 * slow leak that nobody is watching.
 */
const MAX_MEMORY_ENTRIES = 10_000;

type MemoryLimitEntry = {
  windowStarted: number;
  attempts: number;
};

const memoryRateLimitRef = globalThis as unknown as {
  __monolithIngestLimits?: Map<string, MemoryLimitEntry>;
};

function memoryLimits(): Map<string, MemoryLimitEntry> {
  if (!memoryRateLimitRef.__monolithIngestLimits) {
    memoryRateLimitRef.__monolithIngestLimits = new Map<string, MemoryLimitEntry>();
  }
  return memoryRateLimitRef.__monolithIngestLimits;
}

/** The values of the budget setting that have already been complained about. */
const warnedBudgets = new Set<string>();

export function resetMemoryIngestRateLimits(): void {
  memoryLimits().clear();
  warnedBudgets.clear();
}

/**
 * The key one module's budget is counted under.
 *
 * The tenant and the module, never the source address: a module's credential
 * is what identifies it, one address may host several modules, and an address
 * is a thing a caller can change. Hashing the pair keeps the credential
 * itself out of the counter table.
 */
export function ingestRateLimitKey(tenant: string, moduleName: string): string {
  return createHash("sha256").update(`ingest:${tenant}:${moduleName}`).digest("hex");
}

function warnBudgetOnce(raw: string, reason: string): void {
  if (warnedBudgets.has(raw)) return;
  warnedBudgets.add(raw);
  console.warn(
    `[ingest-rate-limit] MONOLITH_INGEST_RATE_LIMIT_EVENTS=${JSON.stringify(raw)} ${reason}; `
      + `using the default of ${DEFAULT_EVENT_BUDGET} events per ${INGEST_RATE_LIMIT_WINDOW_SECONDS}s window.`,
  );
}

/**
 * The event budget one module credential gets per window.
 *
 * A value that is not a positive integer falls back to the default rather
 * than to no limit at all. A mistyped setting that silently removed the
 * control would be indistinguishable from a control that was never there,
 * and the failure would show up only as a flood nobody was watching for.
 * Zero is not an off switch: it is a mistake, and a mistake keeps the
 * default in force.
 */
export function ingestEventBudget(): number {
  const raw = process.env.MONOLITH_INGEST_RATE_LIMIT_EVENTS;
  if (raw === undefined || raw.trim() === "") return DEFAULT_EVENT_BUDGET;
  const value = raw.trim();
  if (!/^\d+$/.test(value)) {
    warnBudgetOnce(value, "is not a positive integer");
    return DEFAULT_EVENT_BUDGET;
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > MAX_EVENT_BUDGET) {
    warnBudgetOnce(value, `is not between 1 and ${MAX_EVENT_BUDGET}`);
    return DEFAULT_EVENT_BUDGET;
  }
  return parsed;
}

/**
 * Keep the in-memory counter table bounded.
 *
 * Expired entries are dropped first, because they carry no information. If
 * the table is still over the bound, the oldest entries go: the oldest
 * counters are the ones closest to expiring anyway, and losing one only
 * means a module gets a fresh window rather than a permanent one.
 */
function enforceMemoryLimitBound(now = Date.now()): void {
  const limits = memoryLimits();
  if (limits.size <= MAX_MEMORY_ENTRIES) return;
  for (const [key, entry] of limits) {
    if (now - entry.windowStarted >= INGEST_RATE_LIMIT_WINDOW_MS) limits.delete(key);
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

/**
 * Charge a batch against a key's window and report the running total.
 *
 * The window is fixed: it starts with the first event of the window and
 * ends a minute later, whatever the traffic looks like inside it.
 */
function chargeMemory(key: string, events: number, now: number): MemoryLimitEntry {
  const limits = memoryLimits();
  const existing = limits.get(key);
  const expired = !existing || now - existing.windowStarted >= INGEST_RATE_LIMIT_WINDOW_MS;
  const entry: MemoryLimitEntry = expired
    ? { windowStarted: now, attempts: events }
    : { windowStarted: existing.windowStarted, attempts: existing.attempts + events };
  limits.set(key, entry);
  enforceMemoryLimitBound(now);
  return entry;
}

/**
 * Charge the shared counter in Postgres.
 *
 * The batch size and the budget travel as transaction-local settings rather
 * than as arguments, so the function keeps a single-argument signature and
 * the limit is configured in exactly one place: the dashboard that owns the
 * modules. A transaction-local setting is dropped when the transaction ends,
 * so a pooled connection cannot carry one module's budget into the next
 * request.
 */
async function chargeInDatabase(
  key: string,
  events: number,
  budget: number,
): Promise<boolean> {
  const client = await getDb().connect();
  try {
    await client.query("begin");
    await client.query(
      "select set_config('monolith.ingest_event_count', $1, true)",
      [String(events)],
    );
    await client.query(
      "select set_config('monolith.ingest_event_budget', $1, true)",
      [String(budget)],
    );
    const result = await client.query<{ allowed: boolean }>(
      "select monolith.record_ingest_attempt($1) as allowed",
      [key],
    );
    await client.query("commit");
    return result.rows[0]?.allowed === true;
  } catch (error) {
    try {
      await client.query("rollback");
    } catch {
      // The connection is unusable; the caller fails closed either way.
    }
    throw error;
  } finally {
    client.release();
  }
}

export type IngestRateLimitResult = {
  /** Whether the batch fits inside the module's budget. */
  allowed: boolean;
  /** The budget in force, in events per window. */
  limit: number;
  /** The events in the window after this batch was charged. */
  charged: number;
  /** When the current window started, in milliseconds since the epoch. */
  windowStarted: number;
  /** How long the module should wait before trying again, in seconds. */
  retryAfterSeconds: number;
};

/**
 * Charge a batch of events against a module's budget.
 *
 * Events are counted, not requests. A module that posted one event per
 * request would otherwise spend a request budget one event at a time and
 * never notice the limit, so a batch of a hundred costs a hundred.
 *
 * A database error other than a missing function is thrown rather than
 * swallowed: the ingest path needs the database to persist the events
 * anyway, so an honest module would be told 503 shortly afterwards
 * regardless, and failing open here would let a flood through exactly when
 * the database is unwell.
 */
export async function chargeIngestEvents(
  tenant: string,
  moduleName: string,
  eventCount: number,
): Promise<IngestRateLimitResult> {
  const key = ingestRateLimitKey(tenant, moduleName);
  const limit = ingestEventBudget();
  const events = Math.max(1, Math.min(eventCount, MAX_EVENT_BUDGET));

  const localResult = (): IngestRateLimitResult => {
    const now = Date.now();
    const memory = chargeMemory(key, events, now);
    return {
      allowed: memory.attempts <= limit,
      limit,
      charged: memory.attempts,
      windowStarted: memory.windowStarted,
      retryAfterSeconds: Math.max(
        1,
        Math.ceil((memory.windowStarted + INGEST_RATE_LIMIT_WINDOW_MS - now) / 1000),
      ),
    };
  };

  if (!process.env.DATABASE_URL) return localResult();

  let sharedAllowed: boolean;
  try {
    sharedAllowed = await chargeInDatabase(key, events, limit);
  } catch (error) {
    // An older database that has not run the ingest rate-limit migration has
    // no such function. The in-memory counter still holds the line there.
    const code =
      typeof error === "object" && error !== null && "code" in error
        ? String((error as { code?: unknown }).code)
        : "";
    if (code !== "42883") throw error;
    return localResult();
  }

  // Both counters have to allow the batch. The shared one covers every
  // instance of the dashboard; the local one is this process's own view of
  // the same window. The local counter is charged only once the shared one
  // has accepted the batch, so a request that failed for an unrelated
  // reason does not spend a budget it never used.
  const result = localResult();
  return { ...result, allowed: result.allowed && sharedAllowed };
}
