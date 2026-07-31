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
  return error instanceof JsonBodyError
    ? Response.json({ error: error.message }, { status: error.status })
    : null;
}
