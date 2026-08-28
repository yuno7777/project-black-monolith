// Postgres-backed operator-login rate limiting.
//
// WHAT THIS FILE IS
// -----------------
// Throttles the login endpoint so a brute-force attacker cannot try millions
// of operator tokens. It delegates the counting to Postgres (the
// monolith.record_operator_login_attempt / clear_operator_login_attempts
// security-definer functions from the
// 20260803092707_add_operator_login_rate_limits migration), which makes the
// limit work ACROSS multiple dashboard instances — the counter lives in the
// shared database, not in one process's memory.
//
// HOW THE KEY IS CHOSEN
// ---------------------
// By default the key is the literal "direct-client" — i.e. ONE shared bucket
// for everyone hitting the dashboard directly (conservative; safe when the
// deployment is a single box). Behind a trusted reverse proxy that overwrites
// X-Forwarded-For, set OPERATOR_TRUST_PROXY_HEADERS=true and the key becomes
// the client IP (hashed), so each user gets their own bucket. Never enable
// the proxy headers unless the proxy really does overwrite them — otherwise
// an attacker can forge the header and evade the limit.
//
// The function returns true while attempts <= 8 within a rolling 15-minute
// window; the login route answers 429 with Retry-After: 900 otherwise, and
// calls clear_operator_login_attempts on a successful login.

import { createHash } from "node:crypto";
import { getDb } from "@/lib/db";

export function operatorRateLimitKey(req: Request): string {
  let source = "direct-client";
  if (process.env.OPERATOR_TRUST_PROXY_HEADERS === "true") {
    source = req.headers.get("x-forwarded-for")?.split(",", 1)[0]?.trim()
      || req.headers.get("x-real-ip")?.trim()
      || source;
  }
  return createHash("sha256").update(`operator-login:${source}`).digest("hex");
}

export async function recordOperatorLoginAttempt(
  req: Request,
): Promise<{ allowed: boolean; key: string }> {
  // Called from: /api/auth/session POST before the credential check. The
  // Postgres function atomically increments the attempt counter for the key
  // (resetting the window after 15 min) and returns attempts <= 8.
  const key = operatorRateLimitKey(req);
  const result = await getDb().query<{ allowed: boolean }>(
    "select monolith.record_operator_login_attempt($1) as allowed",
    [key],
  );
  return { allowed: result.rows[0]?.allowed === true, key };
}

export async function clearOperatorLoginAttempts(key: string): Promise<void> {
  // Called from: /api/auth/session POST on a SUCCESSFUL login, so a legitimate
  // operator who mistyped a few times doesn't stay locked out.
  await getDb().query("select monolith.clear_operator_login_attempts($1)", [key]);
}
