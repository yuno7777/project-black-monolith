import {
  authenticateOperator,
  hasRole,
  lastForwardedValue,
  OperatorAuthUnavailable,
  requestScheme,
  type OperatorIdentity,
  type OperatorRole,
} from "@/lib/operator-auth";

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export function isAuthDisabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const key = "MONOLITH_DISABLE_AUTH";
  // Exact match only. Accepting "True", "TRUE" or " true " would turn a
  // configuration that means nothing on the secure path into one that
  // disables every operator check and grants every requester admin.
  return env[key] === "true";
}

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
export const AUTH_DISABLED = isAuthDisabled();

function demoIdentity(): OperatorIdentity {
  return {
    actor: "auth-disabled",
    role: "admin",
    tenant_id: process.env.MONOLITH_TENANT_ID || "default",
    auth_type: "bearer",
  };
}

if (AUTH_DISABLED) {
  console.warn(
    "[auth] MONOLITH_DISABLE_AUTH=true — operator sign-in is OFF and every "
      + "request is treated as admin. Never run this exposed.",
  );
}

/**
 * A host authority, as RFC 9110 defines one: a name or IP literal, with an
 * optional port.
 *
 * The characters rejected here are the ones that would make the value mean
 * something other than a host. "localhost:3000@evil.example" is a URL whose
 * credentials are "localhost:3000" and whose host is "evil.example", so a
 * Host header of that shape would choose the origin. A browser will not let a
 * page forge Host, but a proxy that forwards `$http_host` verbatim passes
 * along whatever the client sent.
 */
function isPlausibleHost(host: string): boolean {
  if (host.length === 0 || host.length > 255) return false;
  return !/[@\s/?#\\]/.test(host);
}

/** The host the client addressed, before it is checked. */
function hostCandidate(req: Request): string | null {
  const trustProxy = process.env.OPERATOR_TRUST_PROXY_HEADERS === "true";
  const forwardedHost = trustProxy
    ? lastForwardedValue(req.headers.get("x-forwarded-host"))
    : undefined;
  return forwardedHost || req.headers.get("host") || null;
}

/**
 * The scheme, host and port of an origin, or null if the value is not one.
 *
 * Normalising through the URL parser is load-bearing: it case-folds the host
 * and drops a default port, so a proxy that forwards "console.example:443"
 * still matches a browser that sent "https://console.example".
 */
function originOf(raw: string): string | null {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  // "http://user@host" is a URL with credentials, not an origin.
  if (url.username || url.password) return null;
  return url.origin;
}

/**
 * The origin the client actually addressed.
 *
 * `new URL(req.url).origin` is the wrong value inside a container. Next.js
 * builds the request URL from the *server's* own HOSTNAME and PORT, so in the
 * Compose stack every request looks like it came from `http://0.0.0.0:3000`
 * while the browser says `http://localhost:3000` — and every browser mutation
 * was rejected as cross-site, which broke operator sign-in entirely.
 *
 * The Host header is the host the client addressed, and a browser will not let
 * a page forge it, so comparing Origin against it is the same defence with the
 * value that was actually used. A trusted reverse proxy's X-Forwarded-Host
 * wins over Host, because that is the public name the browser used and a proxy
 * that rewrites Host would otherwise make every legitimate request look
 * foreign. `OPERATOR_TRUST_PROXY_HEADERS` gates that, exactly as it gates the
 * Secure cookie flag in `operator-auth.ts`.
 *
 * The forwarded value is the *rightmost* one, because proxies append to these
 * headers: the leftmost is the client's, the rightmost is the closest proxy's.
 * The scheme comes from `requestScheme`, the same helper that decides the
 * cookie's Secure flag, so the two cannot disagree about one request.
 */
export function requestOrigin(req: Request): string | null {
  const host = hostCandidate(req);
  if (!host || !isPlausibleHost(host)) return null;
  return `${requestScheme(req)}://${host}`;
}

/**
 * The origin this request was addressed to, or null when it cannot be told.
 *
 * A Host header that is not an authority is not trimmed into one and then
 * compared: it makes the origin unknowable, and an unknowable origin is
 * refused. Only a request that carried no Host at all falls back to the
 * request URL.
 */
function expectedOrigin(req: Request): string | null {
  const host = hostCandidate(req);
  if (!host) return originOf(req.url);
  const origin = requestOrigin(req);
  return origin ? originOf(origin) : null;
}

/** Reject cross-site browser mutations while preserving non-browser bearer clients. */
export function requireSameOrigin(req: Request): Response | null {
  if (SAFE_METHODS.has(req.method.toUpperCase())) return null;
  const fetchSite = req.headers.get("sec-fetch-site");
  if (fetchSite === "cross-site") {
    return Response.json({ error: "cross-site mutation rejected" }, { status: 403 });
  }
  const origin = req.headers.get("origin");
  if (!origin) return null;
  // Both sides are normalised the same way, so a default port or a
  // differently-cased host still matches the origin the browser sent.
  const expected = expectedOrigin(req);
  const actual = originOf(origin);
  if (!expected || !actual) {
    return Response.json({ error: "request origin is invalid" }, { status: 403 });
  }
  if (actual !== expected) {
    return Response.json({ error: "request origin is not allowed" }, { status: 403 });
  }
  return null;
}

export type AuthenticateOperator = (req: Request) => Promise<OperatorIdentity | null>;

/**
 * Authenticate an API request and enforce its minimum control-plane role.
 *
 * The authenticator is injectable so the same-origin policy for browser
 * sessions can be exercised end to end: resolving a session needs Postgres,
 * and the contract suite runs without a database.
 */
export async function requireOperator(
  req: Request,
  minimum: OperatorRole = "viewer",
  authenticate: AuthenticateOperator = authenticateOperator,
): Promise<OperatorIdentity | Response> {
  if (isAuthDisabled()) return demoIdentity();
  try {
    const identity = await authenticate(req);
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
