import {
  authenticateOperator,
  authenticateOperatorToken,
  createOperatorSession,
  expiredOperatorCookie,
  OperatorAuthUnavailable,
  operatorCookie,
  revokeOperatorSession,
} from "@/lib/operator-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function unavailable(error: unknown): Response | null {
  if (!(error instanceof OperatorAuthUnavailable)) return null;
  console.error("operator authentication is misconfigured", error);
  return Response.json({ error: "operator authentication is unavailable" }, { status: 503 });
}

/** Return the current browser/bearer identity without exposing credentials. */
export async function GET(req: Request) {
  try {
    const identity = await authenticateOperator(req);
    if (!identity) return Response.json({ authenticated: false }, { status: 401 });
    return Response.json({
      authenticated: true,
      actor: identity.actor,
      role: identity.role,
      tenant_id: identity.tenant_id,
    });
  } catch (error) {
    return unavailable(error)
      ?? Response.json({ error: "session validation is temporarily unavailable" }, { status: 503 });
  }
}

/** Exchange a long-lived operator token for an opaque, revocable browser session. */
export async function POST(req: Request) {
  let token = "";
  try {
    const text = await req.text();
    if (text.length > 8 * 1024) {
      return Response.json({ error: "payload exceeds 8 KiB" }, { status: 413 });
    }
    const body = JSON.parse(text) as { token?: unknown };
    token = typeof body?.token === "string" ? body.token.trim() : "";
  } catch {
    return Response.json({ error: "invalid JSON" }, { status: 400 });
  }

  try {
    const identity = authenticateOperatorToken(token);
    if (!identity) {
      return Response.json({ error: "invalid operator credential" }, { status: 401 });
    }
    const session = await createOperatorSession(identity);
    return Response.json(
      {
        authenticated: true,
        actor: identity.actor,
        role: identity.role,
        tenant_id: identity.tenant_id,
      },
      { headers: { "Set-Cookie": operatorCookie(req, session.token, session.maxAge) } },
    );
  } catch (error) {
    return unavailable(error)
      ?? Response.json({ error: "session creation is temporarily unavailable" }, { status: 503 });
  }
}

/** Revoke the current browser session and expire the cookie. */
export async function DELETE(req: Request) {
  try {
    await revokeOperatorSession(req);
  } catch (error) {
    console.error("failed to revoke operator session", error);
    return Response.json({ error: "logout is temporarily unavailable" }, { status: 503 });
  }
  return Response.json(
    { authenticated: false },
    { headers: { "Set-Cookie": expiredOperatorCookie(req) } },
  );
}
