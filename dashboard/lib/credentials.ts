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
