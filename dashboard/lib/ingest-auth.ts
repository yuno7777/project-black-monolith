// Authentication for POST /api/ingest — the module-facing credential check.
//
// WHAT THIS FILE IS
// -----------------
// Decides whether an incoming security event is allowed into the ledger.
// Each detection module (mcp-shield, vector-anchor, trace-audit) holds its OWN
// bearer token, configured per tenant in EVENT_INGEST_TOKENS_JSON:
//
//   {
//     "tenant-a": {
//       "mcp-shield":   "...token...",
//       "vector-anchor": "...token...",
//       "trace-audit":   "...token..."
//     }
//   }
//
// The check is scoped to BOTH the tenant AND the module the event claims:
// a request authenticates only if the presented token matches the expected
// token for (tenant, module) — so one module's token cannot be used to forge
// another module's events, and a token from tenant-a cannot write tenant-b
// events.
//
// WHY TIMING-SAFE COMPARISON
// --------------------------
// A naive `===` on secrets leaks information through timing (an attacker can
// measure how many prefix characters match). Comparing SHA-256 digests with
// timingSafeEqual runs in constant time. Both sides are hashed first so the
// comparison is always over equal-length inputs.
//
// MISCONFIGURATION FAILS CLOSED
// -----------------------------
// If EVENT_INGEST_TOKENS_JSON is missing, unparseable, contains a duplicated
// token (which would make attribution ambiguous), or has no usable
// credentials, configuredTokens() THROWS. The /api/ingest route catches that
// and answers 503 "ingest authentication is unavailable" — an authenticator
// that was never set up must never be mistaken for one that passed.
//
// WHO USES IT
// -----------
// /api/ingest route (app/api/ingest/route.ts) — authenticateIngest(req,
// tenant, module) after the batch has been validated, before any insert.

import { createHash, timingSafeEqual } from "node:crypto";
import { isBearerToken } from "@/lib/credentials";

type TokenMap = Record<string, Record<string, string>>;

function ensureUniqueCredentials(tenants: TokenMap): TokenMap {
  // A token reused across tenants or modules makes attribution ambiguous (who
  // sent this?), so the configuration is treated as unavailable rather than
  // guessing.
  const tokens = Object.values(tenants).flatMap((modules) => Object.values(modules));
  if (new Set(tokens).size !== tokens.length) {
    throw new Error(
      "EVENT_INGEST_TOKENS_JSON must not reuse a token across tenants or modules.",
    );
  }
  return tenants;
}

function configuredTokens(): TokenMap {
  // Parse + validate EVENT_INGEST_TOKENS_JSON. Supports the current
  // tenant-first shape AND the legacy flat module->token shape (treated as
  // the "default" tenant). Throws on anything unusable.
  const raw = process.env.EVENT_INGEST_TOKENS_JSON;
  if (!raw) throw new Error("EVENT_INGEST_TOKENS_JSON is not configured.");
  const parsed: unknown = JSON.parse(raw);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("EVENT_INGEST_TOKENS_JSON must be a module-to-token object.");
  }
  const value = parsed as Record<string, unknown>;
  // Backward compatibility for the original single-tenant module->token map.
  if (Object.values(value).every((token) => typeof token === "string")) {
    const modules = Object.fromEntries(
      Object.entries(value).filter(([, token]) => isBearerToken(token)),
    ) as Record<string, string>;
    if (!Object.keys(modules).length) {
      throw new Error("EVENT_INGEST_TOKENS_JSON has no usable module credentials.");
    }
    return ensureUniqueCredentials({
      default: modules,
    });
  }
  const tenants: TokenMap = Object.create(null) as TokenMap;
  for (const [tenant, rawModules] of Object.entries(value)) {
    if (!tenant || tenant.length > 128 || !rawModules || typeof rawModules !== "object" || Array.isArray(rawModules)) {
      continue;
    }
    const modules = Object.fromEntries(
      Object.entries(rawModules as Record<string, unknown>).filter(
        ([, token]) => isBearerToken(token),
      ),
    ) as Record<string, string>;
    if (Object.keys(modules).length) tenants[tenant] = modules;
  }
  if (!Object.keys(tenants).length) {
    throw new Error("EVENT_INGEST_TOKENS_JSON has no usable tenant/module credentials.");
  }
  return ensureUniqueCredentials(tenants);
}

function sameToken(actual: string, expected: string): boolean {
  // Timing-safe comparison over SHA-256 digests (constant length, constant
  // time).
  const left = createHash("sha256").update(actual).digest();
  const right = createHash("sha256").update(expected).digest();
  return timingSafeEqual(left, right);
}

export function authenticateIngest(req: Request, tenant: string, module: string): boolean {
  // THE check. Called from /api/ingest after normalization: the tenant and
  // module come from the (already validated) first event in the batch, and the
  // Authorization header must carry the matching token.
  const expected = configuredTokens()[tenant]?.[module];
  const header = req.headers.get("authorization");
  const token = header?.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
  return Boolean(expected && isBearerToken(token) && sameToken(token, expected));
}
