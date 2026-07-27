import {
  authenticateOperator,
  hasRole,
  OperatorAuthUnavailable,
  type OperatorIdentity,
  type OperatorRole,
} from "@/lib/operator-auth";

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
