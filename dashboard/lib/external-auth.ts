import {
  createRemoteJWKSet,
  errors as joseErrors,
  jwtVerify,
  type JWTPayload,
} from "jose";
import type { OperatorIdentity, OperatorRole } from "@/lib/operator-auth";

const MAX_EXTERNAL_TOKEN_LENGTH = 8 * 1024;
const keySets = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

export class ExternalAuthUnavailable extends Error {}

function claimObject(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function boundedClaim(...values: unknown[]): string | null {
  for (const value of values) {
    if (typeof value !== "string") continue;
    const trimmed = value.trim();
    if (trimmed && trimmed.length <= 128) return trimmed;
  }
  return null;
}

function operatorRole(value: unknown): OperatorRole | null {
  return value === "viewer" || value === "analyst" || value === "admin" ? value : null;
}

export function externalIdentityFromClaims(payload: JWTPayload): OperatorIdentity | null {
  const metadata = claimObject(payload.app_metadata);
  const actor = boundedClaim(payload.preferred_username, payload.email, payload.sub);
  const role = operatorRole(metadata.monolith_role ?? payload.monolith_role);
  const tenant = boundedClaim(
    metadata.monolith_tenant_id,
    payload.monolith_tenant_id,
    process.env.OPERATOR_OIDC_DEFAULT_TENANT,
  );
  if (!actor || !role || !tenant) return null;
  if (process.env.OPERATOR_OIDC_REQUIRE_MFA === "true" && payload.aal !== "aal2") {
    return null;
  }
  return { actor, role, tenant_id: tenant, auth_type: "bearer" };
}

function externalConfig(): { issuer: string; audience: string; jwksUrl: string } | null {
  const issuer = process.env.OPERATOR_OIDC_ISSUER?.trim();
  const audience = process.env.OPERATOR_OIDC_AUDIENCE?.trim();
  const jwksUrl = process.env.OPERATOR_OIDC_JWKS_URL?.trim();
  if (!issuer && !audience && !jwksUrl) return null;
  if (!issuer || !audience || !jwksUrl) {
    throw new ExternalAuthUnavailable(
      "OPERATOR_OIDC_ISSUER, OPERATOR_OIDC_AUDIENCE, and OPERATOR_OIDC_JWKS_URL must be configured together.",
    );
  }
  try {
    return {
      issuer: new URL(issuer).toString().replace(/\/$/, ""),
      audience,
      jwksUrl: new URL(jwksUrl).toString(),
    };
  } catch {
    throw new ExternalAuthUnavailable("operator OIDC URLs are invalid.");
  }
}

export async function authenticateExternalToken(token: string): Promise<OperatorIdentity | null> {
  const config = externalConfig();
  if (!config) return null;
  if (!token || token.length > MAX_EXTERNAL_TOKEN_LENGTH || token.split(".").length !== 3) {
    return null;
  }
  let keySet = keySets.get(config.jwksUrl);
  if (!keySet) {
    keySet = createRemoteJWKSet(new URL(config.jwksUrl), {
      cooldownDuration: 30_000,
      cacheMaxAge: 10 * 60 * 1000,
      timeoutDuration: 5_000,
    });
    keySets.set(config.jwksUrl, keySet);
  }
  try {
    const { payload } = await jwtVerify(token, keySet, {
      issuer: config.issuer,
      audience: config.audience,
      algorithms: ["RS256", "ES256", "EdDSA"],
      clockTolerance: 5,
    });
    return externalIdentityFromClaims(payload);
  } catch (error) {
    if (error instanceof joseErrors.JOSEError) return null;
    throw error;
  }
}
