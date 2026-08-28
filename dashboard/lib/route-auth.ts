// The shared route guard every protected API uses.
//
// WHAT THIS FILE IS
// -----------------
// Two things:
//   1. requireOperator(req, minimumRole) — authenticate the request and
//      enforce a minimum role. Returns the OperatorIdentity on success, or a
//      Response (401/403/503) the route should return.
//   2. requireSameOrigin(req) — a lightweight CSRF defense for
//      session-authenticated mutations.
//
// THE AUTH CHAIN (what requireOperator does)
// ------------------------------------------
//   req
//    -> authenticateOperator()        (operator-auth.ts)
//         session cookie -> operator_sessions table (digest match, not
//                            revoked, not expired)
//         else Authorization: Bearer -> local bootstrap token, else OIDC JWT
//    -> if session-authenticated: requireSameOrigin() (CSRF)
//    -> hasRole(identity, minimum)   (admin >= analyst >= viewer)
//    -> return identity
//
// FAIL-CLOSED BEHAVIOR
// --------------------
//   - No identity      -> 401.
//   - Wrong role       -> 403.
//   - Auth misconfigured (OperatorAuthUnavailable) -> 503 "unavailable" —
//     an authenticator that was never set up must never be mistaken for one
//     that passed.
//
// THE DEMO ESCAPE HATCH (know this)
// ---------------------------------
// MONOLITH_DISABLE_AUTH="true" (exactly that string, baked at build time)
// skips sign-in entirely: every request is treated as admin and the audit
// trail records the synthetic actor "auth-disabled" — so the trail never
// implies a person signed in when nobody did. Local demos only; the env
// example and docker-compose both warn about it.
//
// CSRF DEFENSE
// ------------
// SameSite=Strict cookies already block most cross-site requests; this check
// is a second layer for mutation routes: session-authenticated requests whose
// Sec-Fetch-Site is "cross-site", or whose Origin doesn't match, are rejected
// with 403. Bearer-token clients (scripts/CI) don't send Origin and pass
// through.

import {
  authenticateOperator,
  hasRole,
  OperatorAuthUnavailable,
  type OperatorIdentity,
  type OperatorRole,
} from "@/lib/operator-auth";

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/**
 * Demo escape hatch: skip operator sign-in entirely.
 *
 * Off unless explicitly set to the exact string "true", so the secure path is
 * what you get by forgetting to configure anything. When on, every request is
 * treated as a full admin, which means anyone who can reach the port can read
 * the ledger and close incidents. Local demos only.
 *
 * The synthetic actor is named for what actually happened rather than borrowing
 * a person's name — the audit trail should not imply someone signed in when
 * nobody did.
 */
export const AUTH_DISABLED = process.env.MONOLITH_DISABLE_AUTH === "true";

const DEMO_IDENTITY: OperatorIdentity = {
  actor: "auth-disabled",
  role: "admin",
  tenant_id: process.env.MONOLITH_TENANT_ID || "default",
  auth_type: "bearer",
};

if (AUTH_DISABLED) {
  console.warn(
    "[auth] MONOLITH_DISABLE_AUTH=true — operator sign-in is OFF and every "
      + "request is treated as admin. Never run this exposed.",
  );
}

/** Reject cross-site browser mutations while preserving non-browser bearer clients.
 * Called from: requireOperator() for session-authenticated requests, and
 * directly by /api/auth/session (login/logout). */
export function requireSameOrigin(req: Request): Response | null {
  if (SAFE_METHODS.has(req.method.toUpperCase())) return null;
  const fetchSite = req.headers.get("sec-fetch-site");
  if (fetchSite === "cross-site") {
    return Response.json({ error: "cross-site mutation rejected" }, { status: 403 });
  }
  const origin = req.headers.get("origin");
  if (!origin) return null; // non-browser client (no Origin header)
  try {
    if (new URL(origin).origin !== new URL(req.url).origin) {
      return Response.json({ error: "request origin is not allowed" }, { status: 403 });
    }
  } catch {
    return Response.json({ error: "request origin is invalid" }, { status: 403 });
  }
  return null;
}

/** Authenticate an API request and enforce its minimum control-plane role.
 *
 * Called from: every protected route — /api/events, /api/incidents (viewer
 * reads, analyst writes), /api/benchmarks, /api/operations, /api/incidents/
 * [eventId]/audit|session|export.
 *
 * Returns the identity for the route to use, or a Response to return.
 */
export async function requireOperator(
  req: Request,
  minimum: OperatorRole = "viewer",
): Promise<OperatorIdentity | Response> {
  if (AUTH_DISABLED) return DEMO_IDENTITY;
  try {
    const identity = await authenticateOperator(req);
    if (!identity) {
      return Response.json({ error: "operator authentication is required" }, { status: 401 });
    }
    if (identity.auth_type === "session") {
      const originError = requireSameOrigin(req);
      if (originError) return originError;
    }
    if (!hasRole(identity, minimum)) {
      return Response.json({ error: `${minimum} role is required` }, { status: 403 });
    }
    return identity;
  } catch (error) {
    if (error instanceof OperatorAuthUnavailable) {
      console.error("operator authentication is misconfigured", error);
      return Response.json({ error: "operator authentication is unavailable" }, { status: 503 });
    }
    console.error("operator session validation failed", error);
    return Response.json({ error: "session validation is temporarily unavailable" }, { status: 503 });
  }
}
