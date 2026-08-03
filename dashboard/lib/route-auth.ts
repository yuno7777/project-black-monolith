import {
  authenticateOperator,
  hasRole,
  OperatorAuthUnavailable,
  type OperatorIdentity,
  type OperatorRole,
} from "@/lib/operator-auth";

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/** Reject cross-site browser mutations while preserving non-browser bearer clients. */
export function requireSameOrigin(req: Request): Response | null {
  if (SAFE_METHODS.has(req.method.toUpperCase())) return null;
  const fetchSite = req.headers.get("sec-fetch-site");
  if (fetchSite === "cross-site") {
    return Response.json({ error: "cross-site mutation rejected" }, { status: 403 });
  }
  const origin = req.headers.get("origin");
  if (!origin) return null;
  try {
    if (new URL(origin).origin !== new URL(req.url).origin) {
      return Response.json({ error: "request origin is not allowed" }, { status: 403 });
    }
  } catch {
    return Response.json({ error: "request origin is invalid" }, { status: 403 });
  }
  return null;
}

/** Authenticate an API request and enforce its minimum control-plane role. */
export async function requireOperator(
  req: Request,
  minimum: OperatorRole = "viewer",
): Promise<OperatorIdentity | Response> {
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
