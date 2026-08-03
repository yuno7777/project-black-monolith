# Identity and access model

Project Black Monolith has three independent principal types. Credentials are
not interchangeable:

| Principal | Credential | Scope | Allowed operations |
| --- | --- | --- | --- |
| Detection module | Per-tenant, per-module bearer token | One tenant and one module | Ingest only |
| Human operator | Bootstrap token, browser session, or validated OIDC JWT | One tenant and one role | Dashboard reads; triage/benchmark writes by role |
| Dashboard runtime | PostgreSQL `monolith_runtime` login → `monolith_app` role | Control-plane tables | Only the SQL verbs needed by the application |

## Tenant and correlation identity

Every event has a required `tenant_id`. Cross-layer agent correlation uses the
complete tuple:

```text
(tenant_id, agent_id, session_id)
```

A `session_id` is not treated as globally unique. Events without both
`agent_id` and `session_id` remain visible, but the dashboard will not infer a
cross-layer session for them.

The application derives an operator's tenant from server-side credential
configuration. It never accepts a tenant, role, or actor from a triage request
body.

## Operator configuration and browser sessions

Configure accounts with role and tenant:

```json
{
  "alice": {
    "token": "a-long-random-bootstrap-token",
    "role": "analyst",
    "tenant_id": "tenant-a"
  },
  "auditor": {
    "token": "another-long-random-token",
    "role": "viewer",
    "tenant_id": "tenant-a"
  }
}
```

Set this JSON as `OPERATOR_TOKENS_JSON`. Legacy
`{"operator":"token"}` maps still work and are interpreted as an `admin` in the
`default` tenant.

The login page exchanges the long-lived token for a 256-bit random browser
session. Only the SHA-256 digest is stored in `monolith.operator_sessions`.
The cookie is `HttpOnly`, `SameSite=Strict`, expires after eight hours by
default, and can be revoked on logout.

- `OPERATOR_SESSION_TTL_SECONDS` changes the lifetime and is clamped to
  5 minutes through 24 hours.
- Cookie `Secure` is enabled for HTTPS requests, including requests behind a
  proxy that sets `X-Forwarded-Proto: https`.
- `OPERATOR_COOKIE_SECURE=true` forces it on; `false` is useful only for local
  HTTP development.

Scripts may continue to send the bootstrap token as
`Authorization: Bearer <token>`. Browser code never stores it in
`localStorage`.

### Production OIDC / Supabase Auth

Configure these values together or leave all three unset:

```text
OPERATOR_OIDC_ISSUER=https://<project-ref>.supabase.co/auth/v1
OPERATOR_OIDC_AUDIENCE=authenticated
OPERATOR_OIDC_JWKS_URL=https://<project-ref>.supabase.co/auth/v1/.well-known/jwks.json
OPERATOR_OIDC_REQUIRE_MFA=true
```

The adapter validates an asymmetric signature through the provider JWKS,
issuer, audience, expiry, and subject. It never derives authorization from a
display name: the JWT must contain a recognized `monolith_role` and an explicit
`tenant_id` (or a deliberately configured `OPERATOR_OIDC_DEFAULT_TENANT`). When
MFA is required, the Supabase `aal` claim must be `aal2`. A valid external
token is exchanged for the same revocable browser-session format as a local
bootstrap credential.

## Dashboard authorization matrix

| Route | Minimum role |
| --- | --- |
| `GET /api/events` | `viewer` |
| `GET /api/incidents` | `viewer` |
| `GET /api/incidents/:id/audit` | `viewer` |
| `GET /api/incidents/:id/session` | `viewer` |
| `GET /api/incidents/:id/export` | `viewer` |
| `POST /api/incidents` | `analyst` |
| `GET /api/benchmarks` | `viewer` |
| `POST /api/benchmarks` | `analyst` |
| `GET /api/operations` | `viewer` |

The `admin` role includes `analyst` and `viewer`; `analyst` includes `viewer`.
Page middleware redirects missing-cookie browser requests to `/login`, while
every API independently validates the session or bearer credential.

## Module and service credentials

`EVENT_INGEST_TOKENS_JSON` is tenant-first:

```json
{
  "tenant-a": {
    "mcp-shield": "one-random-token",
    "vector-anchor": "another-random-token",
    "trace-audit": "a-third-random-token"
  }
}
```

An ingest batch must contain exactly one tenant, and the selected token must
match both that tenant and the event's module. The older flat module-to-token
map remains valid for the `default` tenant.

All bearer credential values must be at least 16 characters. Operator and
module tokens must also be unique: reusing one operator token for two people or
one module token across tenants/modules makes attribution ambiguous, so the
service treats that configuration as unavailable instead of guessing.

VectorAnchor's quarantine/configuration reads, corpus mutation, and detector
reset routes require a separate `MONOLITH_ADMIN_TOKEN`, as does TraceAudit's
detector-configuration read. They fail closed with `503` if it is unconfigured
and with `401` when the bearer token is wrong.

## Database boundary

Migrations run with the administrative connection. The dashboard connection
then uses `SET ROLE monolith_app`, a `NOLOGIN`, `NOSUPERUSER`,
`NOBYPASSRLS` role with:

- immutable event ledger: `SELECT`, `INSERT`;
- incident state: `SELECT`, `INSERT`, `UPDATE`;
- append-only incident audit: `SELECT`, `INSERT`;
- benchmark ledger: `SELECT`, `INSERT`;
- operator sessions: `SELECT`, `INSERT`, `UPDATE`, plus policy-constrained
  `DELETE` only for expired/revoked session cleanup.

The event/audit ledgers grant neither `UPDATE` nor `DELETE`. Row-level security
remains enabled with policies scoped to the runtime role.

Cluster role creation and runtime-password rotation live in
`supabase/bootstrap/001-runtime-role.sh`, which requires administrative
credentials. The one-shot migrator uses a separate administrative connection;
the long-running dashboard receives only `monolith_runtime`, whose unsafe role
attributes are checked and whose membership grants only `monolith_app`.

Every tenant-scoped store operation starts a transaction and sets
`monolith.tenant_id` with transaction-local `set_config`. RLS compares table
rows against that value, while application queries retain explicit tenant
predicates as a second check. A missing context matches no tenant, and the
transaction-local value cannot leak when a pooled connection is reused.

Before the operator's tenant is known, a browser-session lookup sets only the
SHA-256 session digest as transaction-local `monolith.session_hash`; session
RLS permits access only to that one row. Session creation uses the already
authenticated operator tenant.

This database boundary protects the control plane. The agent-facing
`/retrieve` and `/generate` services are still intended to sit on a trusted
service network; their caller identity headers are attribution metadata, not a
general-purpose end-user authentication system.
