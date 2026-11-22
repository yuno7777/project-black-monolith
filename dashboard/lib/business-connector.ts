import { isBearerToken } from "@/lib/credentials";
import { TriageError } from "@/lib/github-triage";
import { readJsonBody } from "@/lib/request-body";
import type { BusinessAction } from "@/lib/business-policy";

function configuredList(name: string): unknown[] {
  const raw = process.env[name];
  if (!raw) return [];
  try {
    const list: unknown = JSON.parse(raw);
    if (Array.isArray(list) && list.length <= 1024) return list;
  } catch { /* Emit a configuration error without exposing any credentials. */ }
  throw new TriageError(503, "business workspace configuration is invalid");
}

function identity(value: unknown): value is string {
  return typeof value === "string" && value.trim() === value && value.length >= 1 &&
    value.length <= 128 && !/[\u0000-\u001f\u007f]/.test(value);
}

export function reviewerTeams(tenant: string, actor: string): string[] {
  let match: string[] | undefined;
  for (const item of configuredList("MONOLITH_BUSINESS_REVIEWERS_JSON")) {
    if (!item || typeof item !== "object" || !("tenant" in item) || !identity(item.tenant) ||
        !("actor" in item) || !identity(item.actor) || !("teams" in item) ||
        !Array.isArray(item.teams) || item.teams.length > 64 || !item.teams.every(identity)) {
      throw new TriageError(503, "business reviewer configuration is invalid");
    }
    if (item.tenant === tenant && item.actor === actor) {
      if (match) throw new TriageError(503, "business reviewer configuration is ambiguous");
      match = item.teams;
    }
  }
  return match ?? [];
}

type DispatchResult = { status: "succeeded" | "failed" | "uncertain"; reference?: string };

function connectorUrl(raw: unknown): string | undefined {
  if (typeof raw !== "string") return undefined;
  try {
    const url = new URL(raw);
    const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if (url.username || url.password || url.hash || url.search ||
        !(url.protocol === "https:" || (url.protocol === "http:" && local))) return undefined;
    return url.toString();
  } catch {
    return undefined;
  }
}

/** Resolve the operator-configured tenant endpoint before claiming an approval. */
export function businessDispatcher(tenant: string) {
  let config: {url: string; token: string} | undefined;
  for (const entry of configuredList("MONOLITH_BUSINESS_CONNECTORS_JSON")) {
    if (!entry || typeof entry !== "object" || !("tenant" in entry) || !identity(entry.tenant) ||
        !("url" in entry) || !("token" in entry) || !isBearerToken(entry.token)) {
      throw new TriageError(503, "business connector configuration is invalid");
    }
    const url = connectorUrl(entry.url);
    if (!url) throw new TriageError(503, "business connector URL is invalid");
    if (entry.tenant === tenant) {
      if (config) throw new TriageError(503, "multiple connectors configured for tenant");
      config = { url, token: entry.token };
    }
  }
  if (!config) throw new TriageError(503, "configure a connector for this tenant before approving");
  const {url, token} = config;
  return async (id: string, action: BusinessAction): Promise<DispatchResult> => {
    try {
      const response = await fetch(url, {
        method: "POST", redirect: "error", cache: "no-store", signal: AbortSignal.timeout(4000),
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json", "idempotency-key": id },
        body: JSON.stringify({ id, tenant, action }),
      });
      if (response.status !== 200) {
        await response.body?.cancel();
        return { status: "uncertain" };
      }
      const receipt = await readJsonBody(response, 2048);
      if (receipt && typeof receipt === "object" && "id" in receipt && receipt.id === id &&
          "status" in receipt && (receipt.status === "succeeded" || receipt.status === "failed") &&
          "reference" in receipt && identity(receipt.reference)) {
        return { status: receipt.status, reference: receipt.reference };
      }
    } catch { /* A lost or malformed acknowledgement cannot prove whether a write occurred. */ }
    return { status: "uncertain" };
  };
}
