import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { withSessionDb, withTenantDb } from "@/lib/db";

/**
 * Operator authentication and revocable browser sessions.
 *
 * Long-lived operator tokens are bootstrap credentials. Browser sign-in trades
 * one for an opaque, HttpOnly, expiring session token; only its SHA-256 digest
 * is stored in Postgres. CI and administrative scripts may continue to use an
 * operator token directly as a bearer credential.
 */

export const OPERATOR_SESSION_COOKIE = "monolith-session";
const MIN_TOKEN_LENGTH = 16;
const MAX_ID_LENGTH = 128;
const DEFAULT_SESSION_TTL_SECONDS = 8 * 60 * 60;

export type OperatorRole = "viewer" | "analyst" | "admin";

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

const ROLE_RANK: Record<OperatorRole, number> = {
  viewer: 0,
  analyst: 1,
  admin: 2,
};

export class OperatorAuthUnavailable extends Error {}

function boundedId(value: unknown, fallback?: string): string | null {
  const resolved = typeof value === "string" ? value.trim() : fallback;
  return resolved && resolved.length <= MAX_ID_LENGTH ? resolved : null;
}

function isRole(value: unknown): value is OperatorRole {
  return value === "viewer" || value === "analyst" || value === "admin";
}

function configuredOperators(): OperatorMap {
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
      if (rawAccount.length >= MIN_TOKEN_LENGTH) {
        accounts[actor] = { token: rawAccount, role: "admin", tenant_id: "default" };
      }
      continue;
    }
    if (!rawAccount || typeof rawAccount !== "object" || Array.isArray(rawAccount)) continue;
    const value = rawAccount as Record<string, unknown>;
    const token = typeof value.token === "string" ? value.token : "";
    const role = isRole(value.role) ? value.role : null;
    const tenant = boundedId(value.tenant_id, "default");
    if (token.length >= MIN_TOKEN_LENGTH && role && tenant) {
      accounts[actor] = { token, role, tenant_id: tenant };
    }
  }
  if (!Object.keys(accounts).length) {
    throw new OperatorAuthUnavailable(
      `OPERATOR_TOKENS_JSON has no usable operator (tokens must be at least ${MIN_TOKEN_LENGTH} characters).`,
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
  const left = createHash("sha256").update(actual).digest();
  const right = createHash("sha256").update(expected).digest();
  return timingSafeEqual(left, right);
}

export function authenticateOperatorToken(token: string): OperatorIdentity | null {
  if (!token) return null;
  const operators = configuredOperators();
  let matched: OperatorIdentity | null = null;
  // Compare every entry so the match position is not disclosed by timing.
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

function cookieValue(req: Request, name: string): string {
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
  return createHash("sha256").update(token).digest("hex");
}

function sessionTtlSeconds(): number {
  const configured = Number(process.env.OPERATOR_SESSION_TTL_SECONDS);
  if (!Number.isFinite(configured)) return DEFAULT_SESSION_TTL_SECONDS;
  return Math.max(5 * 60, Math.min(Math.trunc(configured), 24 * 60 * 60));
}

export async function createOperatorSession(identity: OperatorIdentity): Promise<{
  token: string;
  maxAge: number;
}> {
  const token = randomBytes(32).toString("base64url");
  const maxAge = sessionTtlSeconds();
  await withTenantDb(
    identity.tenant_id,
    async (db) => {
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
        `update monolith.operator_sessions
         set last_seen_at = now()
         where session_hash = $1
           and revoked_at is null
           and expires_at > now()
         returning actor, role, tenant_id`,
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

/** Resolve either an HttpOnly browser session or an explicit bearer token. */
export async function authenticateOperator(req: Request): Promise<OperatorIdentity | null> {
  const session = cookieValue(req, OPERATOR_SESSION_COOKIE);
  if (session) {
    const identity = await authenticateSession(session);
    if (identity) return identity;
  }
  const header = req.headers.get("authorization");
  const bearer = header?.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
  return authenticateOperatorToken(bearer);
}

export function hasRole(identity: OperatorIdentity, minimum: OperatorRole): boolean {
  return ROLE_RANK[identity.role] >= ROLE_RANK[minimum];
}

function requestUsesTls(req: Request): boolean {
  if (process.env.OPERATOR_COOKIE_SECURE === "true") return true;
  if (process.env.OPERATOR_COOKIE_SECURE === "false") return false;
  const forwarded = req.headers.get("x-forwarded-proto")?.split(",", 1)[0]?.trim();
  return forwarded === "https" || new URL(req.url).protocol === "https:";
}

export function operatorCookie(req: Request, token: string, maxAge: number): string {
  const secure = requestUsesTls(req) ? "; Secure" : "";
  return `${OPERATOR_SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure}`;
}

export function expiredOperatorCookie(req: Request): string {
  const secure = requestUsesTls(req) ? "; Secure" : "";
  return `${OPERATOR_SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`;
}
