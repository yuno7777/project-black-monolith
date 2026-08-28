// Operator authentication and revocable browser sessions.
//
// WHAT THIS FILE IS
// -----------------
// The human side of the trust model. It handles THREE credential forms:
//   1. Long-lived operator BOOTSTRAP tokens (OPERATOR_TOKENS_JSON) — used by
//      scripts (and CI) directly as `Authorization: Bearer <token>`.
//   2. Revocable BROWSER SESSIONS — the login page exchanges a bootstrap token
//      for an opaque 256-bit session token; only its SHA-256 digest is stored
//      in Postgres (monolith.operator_sessions). The browser holds the raw
//      token in an HttpOnly, SameSite=Strict, expiring cookie.
//   3. Federated OIDC/Supabase JWTs — delegated to external-auth.ts.
//
// THE "DERIVED, NEVER DECLARED" RULE
// ----------------------------------
// Everything the audit trail needs comes from the CREDENTIAL, never from the
// request body: the actor name is the key the account was configured under,
// the role comes from the account config, the tenant comes from the account
// config. A caller cannot write someone else's name into the audit trail,
// and cannot claim a role or tenant it wasn't granted. (The incidents route
// enforces this by passing identity.actor into normalizeTransition.)
//
// WHY STORE ONLY THE DIGEST
// -------------------------
// A database read must never be replayable as a browser credential. If the
// operator_sessions table leaked, the attacker would get SHA-256 digests —
// useless for impersonation — rather than usable session tokens.
//
// WHY TIMING-SAFE COMPARISON
// --------------------------
// sameSecret() compares SHA-256 digests with timingSafeEqual (constant time).
// authenticateOperatorToken() also compares EVERY configured account (not
// just until the first match) so the match position is not disclosed by
// timing.
//
// FAIL-CLOSED ON MISCONFIGURATION
// -------------------------------
// If OPERATOR_TOKENS_JSON is missing/unusable, configuredOperators() throws
// OperatorAuthUnavailable; route-auth.ts converts that to 503. An
// authenticator that was never set up must never be mistaken for one that
// passed.

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { isBearerToken } from "@/lib/credentials";
import { withSessionDb, withTenantDb } from "@/lib/db";
import { authenticateExternalToken } from "@/lib/external-auth";

export const OPERATOR_SESSION_COOKIE = "monolith-session";
const MAX_ID_LENGTH = 128;
const DEFAULT_SESSION_TTL_SECONDS = 8 * 60 * 60;

export type OperatorRole = "viewer" | "analyst" | "admin";

/** The resolved identity of an authenticated operator. `actor` and `tenant_id`
 * are always derived server-side from the credential. */
export interface OperatorIdentity {
  actor: string;
  role: OperatorRole;
  tenant_id: string;
  auth_type: "bearer" | "session";
}

interface OperatorAccount {
  token: string;
  role: OperatorRole;
  tenant_id: string;
}

type OperatorMap = Record<string, OperatorAccount>;

// Role hierarchy: admin >= analyst >= viewer. hasRole() compares ranks.
const ROLE_RANK: Record<OperatorRole, number> = {
  viewer: 0,
  analyst: 1,
  admin: 2,
};

/** Thrown when operator auth is not configured correctly — route-auth.ts
 * turns it into a 503 (fail closed). */
export class OperatorAuthUnavailable extends Error {}

function boundedId(value: unknown, fallback?: string): string | null {
  const resolved = typeof value === "string" ? value.trim() : fallback;
  return resolved && resolved.length <= MAX_ID_LENGTH ? resolved : null;
}

function isRole(value: unknown): value is OperatorRole {
  return value === "viewer" || value === "analyst" || value === "admin";
}

function configuredOperators(): OperatorMap {
  // Parse OPERATOR_TOKENS_JSON:
  //   { "alice": {"token": "...", "role": "analyst", "tenant_id": "tenant-a"} }
  // Legacy { "operator": "token" } string entries still work and mean
  // admin/default. Rejects unusable configs loudly (see file header).
  const raw = process.env.OPERATOR_TOKENS_JSON;
  if (!raw) {
    throw new OperatorAuthUnavailable("OPERATOR_TOKENS_JSON is not configured.");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new OperatorAuthUnavailable("OPERATOR_TOKENS_JSON must be valid JSON.");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new OperatorAuthUnavailable(
      "OPERATOR_TOKENS_JSON must be an operator-to-account object.",
    );
  }

  const accounts: OperatorMap = Object.create(null) as OperatorMap;
  for (const [rawName, rawAccount] of Object.entries(parsed as Record<string, unknown>)) {
    const actor = boundedId(rawName);
    if (!actor) continue;

    // Legacy string entries remain valid and are treated as single-tenant
    // administrators. New deployments should use {token, role, tenant_id}.
    if (typeof rawAccount === "string") {
      if (isBearerToken(rawAccount)) {
        accounts[actor] = { token: rawAccount, role: "admin", tenant_id: "default" };
      }
      continue;
    }
    if (!rawAccount || typeof rawAccount !== "object" || Array.isArray(rawAccount)) continue;
    const value = rawAccount as Record<string, unknown>;
    const token = typeof value.token === "string" ? value.token : "";
    const role = isRole(value.role) ? value.role : null;
    const tenant = boundedId(value.tenant_id, "default");
    if (isBearerToken(token) && role && tenant) {
      accounts[actor] = { token, role, tenant_id: tenant };
    }
  }
  if (!Object.keys(accounts).length) {
    throw new OperatorAuthUnavailable(
      "OPERATOR_TOKENS_JSON has no usable operator (tokens must be 16-512 header-safe characters).",
    );
  }
  const tokens = Object.values(accounts).map((account) => account.token);
  if (new Set(tokens).size !== tokens.length) {
    throw new OperatorAuthUnavailable(
      "OPERATOR_TOKENS_JSON must not reuse a token across operators.",
    );
  }
  return accounts;
}

function sameSecret(actual: string, expected: string): boolean {
  // Constant-time comparison over SHA-256 digests.
  const left = createHash("sha256").update(actual).digest();
  const right = createHash("sha256").update(expected).digest();
  return timingSafeEqual(left, right);
}

export function authenticateOperatorToken(token: string): OperatorIdentity | null {
  // Resolve a bootstrap token to an identity. Compares EVERY entry so the
  // match position is not disclosed by timing.
  if (!isBearerToken(token)) return null;
  const operators = configuredOperators();
  let matched: OperatorIdentity | null = null;
  for (const [actor, account] of Object.entries(operators)) {
    if (sameSecret(token, account.token)) {
      matched = {
        actor,
        role: account.role,
        tenant_id: account.tenant_id,
        auth_type: "bearer",
      };
    }
  }
  return matched;
}

export async function authenticateOperatorCredential(token: string): Promise<OperatorIdentity | null> {
  // Local bootstrap token first; if that doesn't match, try the OIDC/Supabase
  // adapter (external-auth.ts). Used by login and by the bearer path.
  return authenticateOperatorToken(token) ?? authenticateExternalToken(token);
}

function cookieValue(req: Request, name: string): string {
  // Minimal cookie parsing (the only cookie the app sets is the session).
  const raw = req.headers.get("cookie") ?? "";
  for (const pair of raw.split(";")) {
    const [key, ...parts] = pair.trim().split("=");
    if (key === name) {
      try {
        return decodeURIComponent(parts.join("="));
      } catch {
        return "";
      }
    }
  }
  return "";
}

function sessionHash(token: string): string {
  // Only the SHA-256 digest is ever stored or looked up in the database.
  return createHash("sha256").update(token).digest("hex");
}

function sessionTtlSeconds(): number {
  // OPERATOR_SESSION_TTL_SECONDS, clamped to [5 minutes, 24 hours].
  const configured = Number(process.env.OPERATOR_SESSION_TTL_SECONDS);
  if (!Number.isFinite(configured)) return DEFAULT_SESSION_TTL_SECONDS;
  return Math.max(5 * 60, Math.min(Math.trunc(configured), 24 * 60 * 60));
}

export async function createOperatorSession(identity: OperatorIdentity): Promise<{
  token: string;
  maxAge: number;
}> {
  // Called from: /api/auth/session POST after a successful credential check.
  // Generates a 32-byte random session token, stores its digest (with actor,
  // role, tenant, expiry) in Postgres, opportunistically garbage-collects the
  // tenant's expired/revoked rows, and returns the raw token + lifetime for
  // the Set-Cookie header (operatorCookie()).
  const token = randomBytes(32).toString("base64url");
  const maxAge = sessionTtlSeconds();
  await withTenantDb(
    identity.tenant_id,
    async (db) => {
      await db.query(
        `delete from monolith.operator_sessions
         where tenant_id = $1 and (expires_at <= now() or revoked_at is not null)`,
        [identity.tenant_id],
      );
      await db.query(
        `insert into monolith.operator_sessions
           (session_hash, actor, role, tenant_id, expires_at)
         values ($1, $2, $3, $4, now() + ($5 * interval '1 second'))`,
        [sessionHash(token), identity.actor, identity.role, identity.tenant_id, maxAge],
      );
    },
  );
  return { token, maxAge };
}

async function authenticateSession(token: string): Promise<OperatorIdentity | null> {
  // Resolve a session cookie to an identity. Runs under withSessionDb(hash),
  // so the RLS policy scopes the lookup to exactly this session's digest (a
  // wrong hash matches nothing). A session is valid only while not revoked and
  // not expired; last_seen_at is refreshed at most every 5 minutes to avoid a
  // write per request.
  if (!token || token.length > 128) return null;
  const hash = sessionHash(token);
  return withSessionDb(
    hash,
    async (db) => {
      const result = await db.query<{
        actor: string;
        role: OperatorRole;
        tenant_id: string;
      }>(
        `with valid as (
           select session_hash, actor, role, tenant_id
           from monolith.operator_sessions
           where session_hash = $1
             and revoked_at is null
             and expires_at > now()
         ), touched as (
           update monolith.operator_sessions sessions
           set last_seen_at = now()
           from valid
           where sessions.session_hash = valid.session_hash
             and sessions.last_seen_at < now() - interval '5 minutes'
           returning sessions.session_hash
         )
         select actor, role, tenant_id from valid`,
        [hash],
      );
      const row = result.rows[0];
      return row
        ? { actor: row.actor, role: row.role, tenant_id: row.tenant_id, auth_type: "session" }
        : null;
    },
  );
}

export async function revokeOperatorSession(req: Request): Promise<void> {
  // Called from: /api/auth/session DELETE (logout). Marks the session revoked
  // in the database so even an unexpired cookie stops working.
  const token = cookieValue(req, OPERATOR_SESSION_COOKIE);
  if (!token) return;
  const hash = sessionHash(token);
  await withSessionDb(
    hash,
    async (db) => {
      await db.query(
        `update monolith.operator_sessions
         set revoked_at = coalesce(revoked_at, now())
         where session_hash = $1`,
        [hash],
      );
    },
  );
}

/** Resolve either an HttpOnly browser session or an explicit bearer token.
 * Called from: route-auth.ts requireOperator() for every protected route. */
export async function authenticateOperator(req: Request): Promise<OperatorIdentity | null> {
  const session = cookieValue(req, OPERATOR_SESSION_COOKIE);
  if (session) {
    const identity = await authenticateSession(session);
    if (identity) return identity;
  }
  const header = req.headers.get("authorization");
  const bearer = header?.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
  return authenticateOperatorCredential(bearer);
}

export function hasRole(identity: OperatorIdentity, minimum: OperatorRole): boolean {
  // admin >= analyst >= viewer.
  return ROLE_RANK[identity.role] >= ROLE_RANK[minimum];
}

function requestUsesTls(req: Request): boolean {
  // Whether to add the Secure flag: forced on/off by env, else inferred from
  // X-Forwarded-Proto (behind a proxy) or the request URL.
  if (process.env.OPERATOR_COOKIE_SECURE === "true") return true;
  if (process.env.OPERATOR_COOKIE_SECURE === "false") return false;
  const forwarded = req.headers.get("x-forwarded-proto")?.split(",", 1)[0]?.trim();
  return forwarded === "https" || new URL(req.url).protocol === "https:";
}

export function operatorCookie(req: Request, token: string, maxAge: number): string {
  // The Set-Cookie value for a new session: HttpOnly (no JS access),
  // SameSite=Strict (CSRF defense), expiring, optionally Secure.
  const secure = requestUsesTls(req) ? "; Secure" : "";
  return `${OPERATOR_SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure}`;
}

export function expiredOperatorCookie(req: Request): string {
  // The Set-Cookie value for logout (Max-Age=0 deletes the cookie).
  const secure = requestUsesTls(req) ? "; Secure" : "";
  return `${OPERATOR_SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`;
}
