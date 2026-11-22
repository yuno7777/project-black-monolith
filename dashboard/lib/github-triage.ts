import { createHash, timingSafeEqual } from "node:crypto";

const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const TOKEN = /^[A-Za-z0-9._~+/=-]{32,512}$/;
const REPOSITORY = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/;

export class TriageError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

export type Workload = { tenant: string; agent: string; session: string };
export type GitHubAction = { kind: "reply" | "add_label" | "remove_label"; value: string };

export function githubConfig(): { tenant: string; repository: string; token: string } {
  const tenant = process.env.MONOLITH_TENANT_ID || "default";
  const repository = process.env.MONOLITH_GITHUB_REPOSITORY ?? "";
  const token = process.env.MONOLITH_GITHUB_TOKEN ?? "";
  if (process.env.MONOLITH_DISABLE_AUTH === "true" || !ID.test(tenant) || !REPOSITORY.test(repository) ||
      repository.endsWith("/.") || repository.endsWith("/..") || !TOKEN.test(token)) {
    throw new TriageError(503, "GitHub triage is unavailable");
  }
  return { tenant, repository, token };
}

export function githubWorkload(req: Request, tenant: string): Workload {
  const token = req.headers.get("x-monolith-workload-token") ?? "";
  if (!TOKEN.test(token)) throw new TriageError(401, "invalid workload credential");
  let grants: unknown;
  try {
    grants = JSON.parse(process.env.MONOLITH_WORKLOAD_GRANTS_JSON ?? "");
  } catch {
    throw new TriageError(503, "workload authorization is unavailable");
  }
  if (!Array.isArray(grants) || grants.length < 1 || grants.length > 256) {
    throw new TriageError(503, "workload authorization is unavailable");
  }
  const provided = createHash("sha256").update(token).digest();
  const known = new Set<string>();
  let identity: Workload | undefined;
  for (const grant of grants) {
    if (!grant || typeof grant !== "object" || Object.keys(grant).length !== 3 ||
        typeof grant.token_sha256 !== "string" || !DIGEST.test(grant.token_sha256) ||
        typeof grant.agent_id !== "string" || !ID.test(grant.agent_id) ||
        typeof grant.session_id !== "string" || !ID.test(grant.session_id) || known.has(grant.token_sha256)) {
      throw new TriageError(503, "workload authorization is unavailable");
    }
    known.add(grant.token_sha256);
    if (timingSafeEqual(provided, Buffer.from(grant.token_sha256, "hex"))) {
      identity = { tenant, agent: grant.agent_id, session: grant.session_id };
    }
  }
  if (!identity) throw new TriageError(401, "invalid workload credential");
  for (const [key, expected] of Object.entries(identity)) {
    const claim = req.headers.get(`x-monolith-${key}-id`);
    if (claim !== null && claim !== expected) throw new TriageError(403, "workload identity does not match its grant");
  }
  return identity;
}

export function issueNumber(value: unknown): number {
  if (!Number.isSafeInteger(value) || Number(value) < 1 || Number(value) > 2147483647) {
    throw new TriageError(422, "issue must be a positive integer");
  }
  return Number(value);
}

export function githubAction(value: unknown): GitHubAction {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length !== 2) {
    throw new TriageError(422, "an action kind and value are required");
  }
  const { kind, value: content } = value as Record<string, unknown>;
  if (typeof content !== "string" || !content.trim() || content.includes("\0")) {
    throw new TriageError(422, "action content is invalid");
  }
  if (kind === "reply" && Buffer.byteLength(content) <= 12000) return { kind, value: content };
  if ((kind === "add_label" || kind === "remove_label") && content === content.trim() &&
      !/[\u0000-\u001f\u007f]/.test(content) && Buffer.byteLength(content) <= 50 &&
      content !== "." && content !== "..") return { kind, value: content };
  throw new TriageError(422, "unsupported action or content length");
}

export function actionDigest(workload: Workload, repository: string, issue: number, action: GitHubAction): string {
  return createHash("sha256").update(JSON.stringify([
    workload.tenant, workload.agent, workload.session, repository, issue, action.kind, action.value,
  ])).digest("hex");
}

function githubRequest(config: ReturnType<typeof githubConfig>, path: string, method = "GET", body?: object) {
  return fetch(`https://api.github.com/repos/${config.repository}/issues/${path}`, {
    method,
    headers: {
      authorization: `Bearer ${config.token}`,
      accept: "application/vnd.github+json",
      "content-type": "application/json",
      "x-github-api-version": "2022-11-28",
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: "error",
    signal: AbortSignal.timeout(4000),
    cache: "no-store",
  });
}

export async function readIssue(config: ReturnType<typeof githubConfig>, issue: number) {
  const response = await githubRequest(config, String(issue));
  if (response.status === 404) throw new TriageError(404, "issue not found");
  if (!response.ok) throw new TriageError(502, "GitHub could not read the issue");
  const data = await response.json();
  if (data.pull_request) throw new TriageError(404, "issue not found");
  return {
    number: issue,
    repository: config.repository,
    title: String(data.title ?? "").slice(0, 256),
    body: String(data.body ?? "").slice(0, 16000),
    labels: Array.isArray(data.labels) ? data.labels.slice(0, 100).map((label: {name?: string}) => label.name) : [],
  };
}

export async function writeIssue(config: ReturnType<typeof githubConfig>, issue: number, action: GitHubAction) {
  const response = action.kind === "reply"
    ? await githubRequest(config, `${issue}/comments`, "POST", { body: action.value })
    : action.kind === "add_label"
      ? await githubRequest(config, `${issue}/labels`, "POST", { labels: [action.value] })
      : await githubRequest(config, `${issue}/labels/${encodeURIComponent(action.value)}`, "DELETE");
  const status = response.status;
  let commentId: string | null = null;
  if (status === 201 && action.kind === "reply") {
    const data = await response.json();
    if (!Number.isSafeInteger(data.id)) throw new Error("GitHub comment id is unavailable");
    commentId = String(data.id);
  } else {
    await response.body?.cancel();
  }
  return { status, commentId };
}

export function triageResponse(error: unknown): Response {
  if (error instanceof TriageError) return Response.json({ error: error.message }, { status: error.status });
  console.error("GitHub triage request failed", error instanceof Error ? error.name : "unknown");
  return Response.json({ error: "GitHub triage is temporarily unavailable" }, { status: 503 });
}
