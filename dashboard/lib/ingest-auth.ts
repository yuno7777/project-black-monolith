import { createHash, timingSafeEqual } from "node:crypto";

type TokenMap = Record<string, Record<string, string>>;

function ensureUniqueCredentials(tenants: TokenMap): TokenMap {
  const tokens = Object.values(tenants).flatMap((modules) => Object.values(modules));
  if (new Set(tokens).size !== tokens.length) {
    throw new Error(
      "EVENT_INGEST_TOKENS_JSON must not reuse a token across tenants or modules.",
    );
  }
  return tenants;
}

function configuredTokens(): TokenMap {
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
      Object.entries(value).filter(([, token]) => (token as string).length >= 16),
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
        ([, token]) => typeof token === "string" && token.length >= 16,
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
  const left = createHash("sha256").update(actual).digest();
  const right = createHash("sha256").update(expected).digest();
  return timingSafeEqual(left, right);
}

export function authenticateIngest(req: Request, tenant: string, module: string): boolean {
  const expected = configuredTokens()[tenant]?.[module];
  const header = req.headers.get("authorization");
  const token = header?.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
  return Boolean(expected && token && sameToken(token, expected));
}
