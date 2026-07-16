import { timingSafeEqual } from "node:crypto";

/**
 * Operator (human) authentication for the incident lifecycle.
 *
 * Separate from `ingest-auth` on purpose: those credentials identify *modules*
 * and are scoped so one module cannot forge another's events. A module token is
 * the wrong credential for a person, and reusing one here would mean any module
 * could close its own findings.
 *
 * The important property is that the actor is *derived from the token* and is
 * never read from the request body. An audit trail whose actor is self-declared
 * records only what the caller wished to be called, which is worse than no
 * trail at all — it looks like evidence.
 */

type OperatorMap = Record<string, string>;

const MIN_TOKEN_LENGTH = 16;

export class OperatorAuthUnavailable extends Error {}

function configuredOperators(): OperatorMap {
  const raw = process.env.OPERATOR_TOKENS_JSON;
  if (!raw) {
    throw new OperatorAuthUnavailable("OPERATOR_TOKENS_JSON is not configured.");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new OperatorAuthUnavailable("OPERATOR_TOKENS_JSON must be valid JSON.");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new OperatorAuthUnavailable(
      "OPERATOR_TOKENS_JSON must be an operator-to-token object.",
    );
  }
  const entries = Object.entries(parsed as Record<string, unknown>).filter(
    ([name, token]) =>
      name.length > 0 && typeof token === "string" && token.length >= MIN_TOKEN_LENGTH,
  ) as [string, string][];
  if (!entries.length) {
    throw new OperatorAuthUnavailable(
      `OPERATOR_TOKENS_JSON has no usable operator (tokens must be at least ${MIN_TOKEN_LENGTH} characters).`,
    );
  }
  return Object.fromEntries(entries);
}

function sameToken(actual: string, expected: string): boolean {
  const left = Buffer.from(actual);
  const right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}

/**
 * Resolve the bearer token to the operator it belongs to.
 *
 * Returns the operator's name, or null if the credential is absent or unknown.
 * Throws `OperatorAuthUnavailable` when nothing is configured — the caller
 * turns that into a 503 and fails closed, because an authenticator that has not
 * been set up must never be mistaken for one that passed.
 */
export function authenticateOperator(req: Request): string | null {
  const operators = configuredOperators();
  const header = req.headers.get("authorization");
  const token = header?.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
  if (!token) return null;

  // Every candidate is compared, with no early exit, so the time taken does not
  // reveal how many operators are configured or how far down the list a
  // guessed token matched.
  let matched: string | null = null;
  for (const [name, expected] of Object.entries(operators)) {
    if (sameToken(token, expected)) matched = name;
  }
  return matched;
}
