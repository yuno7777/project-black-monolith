// Hard-bounded JSON body reading for API routes.
//
// WHAT THIS FILE IS
// -----------------
// The dashboard's shared request-body parser. Every route that accepts a body
// (/api/ingest, /api/auth/session, /api/incidents POST, /api/benchmarks POST)
// uses readJsonBody(req, maxBytes) instead of await req.json(), because
// req.json() trusts Content-Length and would happily slurp an unbounded
// chunked body into memory.
//
// WHAT IT DOES
// ------------
//   1. If Content-Length is present, validate it is a pure digit string and
//      <= maxBytes (a lying or oversized header -> 400/413 immediately).
//   2. Otherwise stream the body through a reader, counting bytes as they
//      arrive, and abort with 413 the moment the cap is exceeded.
//   3. Decode strictly as UTF-8 (TextDecoder fatal: true — invalid UTF-8 is a
//      400, not silent replacement) and JSON.parse.
//
// Errors are typed (JsonBodyError with a status) so routes can map them to
// responses with jsonBodyError().

export class JsonBodyError extends Error {
  constructor(
    message: string,
    readonly status: 400 | 413,
  ) {
    super(message);
  }
}

/** Read a JSON body with a hard UTF-8 byte limit, including chunked bodies. */
export async function readJsonBody(req: Request, maxBytes: number): Promise<unknown> {
  const declared = req.headers.get("content-length");
  if (declared !== null) {
    if (!/^\d+$/.test(declared)) {
      throw new JsonBodyError("invalid Content-Length", 400);
    }
    if (Number(declared) > maxBytes) {
      throw new JsonBodyError(`payload exceeds ${maxBytes} bytes`, 413);
    }
  }

  const reader = req.body?.getReader();
  if (!reader) throw new JsonBodyError("invalid JSON", 400);
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new JsonBodyError(`payload exceeds ${maxBytes} bytes`, 413);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return JSON.parse(text);
  } catch {
    throw new JsonBodyError("invalid JSON", 400);
  }
}

export function jsonBodyError(error: unknown): Response | null {
  // Map a JsonBodyError to an HTTP response (400/413); anything else returns
  // null so the route's own error handling runs.
  return error instanceof JsonBodyError
    ? Response.json({ error: error.message }, { status: error.status })
    : null;
}
