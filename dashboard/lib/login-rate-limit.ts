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
  const key = operatorRateLimitKey(req);
  const result = await getDb().query<{ allowed: boolean }>(
    "select monolith.record_operator_login_attempt($1) as allowed",
    [key],
  );
  return { allowed: result.rows[0]?.allowed === true, key };
}

export async function clearOperatorLoginAttempts(key: string): Promise<void> {
  await getDb().query("select monolith.clear_operator_login_attempts($1)", [key]);
}
