// The shared rule for what counts as an acceptable bearer token.
//
// Every credential in the system (module ingest tokens, operator tokens,
// admin tokens) must be 16-512 characters of "header-safe" characters —
// alphanumerics plus the URL-safe set. Two reasons:
//   1. The tokens are embedded in Authorization headers; characters like
//      newlines or spaces could break header parsing (header injection).
//   2. A minimum length guarantees tokens have real entropy — a 5-char
//      "token" would be guessable.
//
// The same rule is enforced on the module side:
//   python-common _valid_bearer_token, vector-anchor/trace-audit config.py,
//   mcp-shield outbox.rs valid_event_token.
// It is checked in ONE place on the dashboard so no route can accidentally
// accept a malformed token.

const MIN_BEARER_TOKEN_BYTES = 16;
const MAX_BEARER_TOKEN_BYTES = 512;
const BEARER_TOKEN = /^[A-Za-z0-9\-._~+/=]+$/;

export function isBearerToken(value: unknown): value is string {
  return (
    typeof value === "string"
    && value.length >= MIN_BEARER_TOKEN_BYTES
    && value.length <= MAX_BEARER_TOKEN_BYTES
    && BEARER_TOKEN.test(value)
  );
}
