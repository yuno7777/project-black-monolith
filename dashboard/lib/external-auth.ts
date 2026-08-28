// Federated operator authentication: OIDC / Supabase Auth JWT validation.
//
// WHAT THIS FILE IS
// -----------------
// The third credential form in the trust model. When configured (all three of
// OPERATOR_OIDC_ISSUER / OPERATOR_OIDC_AUDIENCE / OPERATOR_OIDC_JWKS_URL), an
// operator can authenticate with an access token issued by Supabase Auth (or
// any OIDC provider) instead of a local bootstrap token.
//
// HOW IT WORKS
// ------------
//   1. The presented token must be a 3-part JWT (header.payload.signature).
//   2. Its signature is verified against the provider's JSON Web Key Set
//      (JWKS) — fetched once per URL and cached (createRemoteJWKSet with
//      10-minute cache, 30s cooldown, 5s timeout). Only asymmetric algorithms
//      (RS256/ES256/EdDSA) are accepted.
//   3. Issuer, audience, expiry, and a 5-second clock tolerance are validated
//      by jose's jwtVerify.
//   4. Authorization is derived from CLAIMS, never from a display name:
//        actor  = preferred_username | email | sub
//        role   = app_metadata.monolith_role | payload.monolith_role
//        tenant = app_metadata.monolith_tenant_id | payload.monolith_tenant_id
//                 | OPERATOR_OIDC_DEFAULT_TENANT
//      A token missing role or tenant is REJECTED (return null) even though
//      its signature was valid — the provider proved WHO you are; the claims
//      decide WHAT you may do.
//   5. If OPERATOR_OIDC_REQUIRE_MFA is "true" (the default), the Supabase
//      `aal` claim must be "aal2" (second-factor authentication).
//
// A valid external token is treated exactly like a local bootstrap token
// (auth_type: "bearer") and can be exchanged for a browser session at login.
//
// WHO USES IT
// -----------
// operator-auth.ts authenticateOperatorCredential() — tried only when the
// local token check fails.

import {
  createRemoteJWKSet,
  errors as joseErrors,
  jwtVerify,
  type JWTPayload,
} from "jose";
import type { OperatorIdentity, OperatorRole } from "@/lib/operator-auth";

const MAX_EXTERNAL_TOKEN_LENGTH = 8 * 1024;
// jwksUrl -> cached key set (one fetch per provider).
const keySets = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

export class ExternalAuthUnavailable extends Error {}

function claimObject(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function boundedClaim(...values: unknown[]): string | null {
  // First usable (non-blank, <=128 chars) claim among the candidates.
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
  // Map verified JWT claims to an OperatorIdentity. Returns null (reject)
  // unless actor + role + tenant are all present and (when required) MFA
  // (aal2) was used.
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
  // All three vars or none. A partial config is a configuration ERROR
  // (thrown), not "disabled" — half-configured auth must fail closed.
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
  // Called from: operator-auth.ts authenticateOperatorCredential().
  // Returns null for any invalid/unverifiable token (treated as "not a
  // federated operator"); throws only on configuration problems (fail closed).
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
