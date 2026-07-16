import { timingSafeEqual } from "node:crypto";

type TokenMap = Record<string, string>;

function configuredTokens(): TokenMap {
  const raw = process.env.EVENT_INGEST_TOKENS_JSON;
  if (!raw) throw new Error("EVENT_INGEST_TOKENS_JSON is not configured.");
  const parsed: unknown = JSON.parse(raw);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("EVENT_INGEST_TOKENS_JSON must be a module-to-token object.");
  }
  return Object.fromEntries(
    Object.entries(parsed as Record<string, unknown>).filter(
      ([, token]) => typeof token === "string" && token.length >= 16,
    ),
  ) as TokenMap;
}

function sameToken(actual: string, expected: string): boolean {
  const left = Buffer.from(actual);
  const right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}

export function authenticateIngest(req: Request, module: string): boolean {
  const expected = configuredTokens()[module];
  const header = req.headers.get("authorization");
  const token = header?.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
  return Boolean(expected && token && sameToken(token, expected));
}
