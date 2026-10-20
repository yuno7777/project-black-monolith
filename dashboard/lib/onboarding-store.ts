import { existsSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { isBearerToken } from "@/lib/credentials";
import { withTenantDb } from "@/lib/db";
import { getMemoryEventsForTenant } from "@/lib/event-store";
import { moduleAdminUrl, probeModuleRuntimes } from "@/lib/operations-store";
import { KNOWN_MODULES, type ModuleName, type Severity } from "@/lib/types";

/**
 * The read side of "is this stack ready for my agent?".
 *
 * Everything here answers a question the operator would otherwise answer by
 * running a command and reading its output. The dashboard can answer the
 * questions that live inside the stack (are the three layers answering, does
 * the memory layer have a corpus, has an agent session been filed) and it can
 * render the ones that live on the host (is the tool layer built, what
 * command starts the agent). It never renders a credential: the launcher
 * reads the repository's own `.env`, so the command it needs carries none.
 */

export const MAX_RECENT_SESSIONS = 100;
export const DEFAULT_RECENT_SESSIONS = 20;

export type OnboardingStepState = "ready" | "todo" | "blocked" | "unknown";

export type OnboardingStep = {
  id: string;
  label: string;
  state: OnboardingStepState;
  detail: string;
  /** What the operator has to do, when the step is not ready. */
  action?: { kind: "command" | "button" | "link"; label: string; payload?: string };
};

export type RecentSession = {
  session_id: string;
  agent_id: string | null;
  events: number;
  modules: ModuleName[];
  worst_severity: Severity;
  first_ms: number | null;
  last_ms: number | null;
};

export type CorpusState = {
  configured: boolean;
  reachable: boolean;
  documents: number;
  quarantined: number;
  error?: string;
};

export type ShieldBinaryState = {
  /** False when the repository is not on this process's filesystem. */
  checked: boolean;
  found: boolean;
  path: string | null;
  hint: string;
};

export type OnboardingState = {
  generated_at_ms: number;
  tenant_id: string;
  stack: {
    modules: Array<{ module: string; configured: boolean; reachable: boolean; status?: number }>;
    reachable: boolean;
  };
  corpus: CorpusState;
  shield_binary: ShieldBinaryState;
  sessions: RecentSession[];
  steps: OnboardingStep[];
};

const SEVERITY_RANK: Record<string, number> = { info: 0, warning: 1, critical: 2 };

/**
 * Narrow a module name to the three the contract defines.
 *
 * The ledger's `module` column is checked against those three, so anything
 * else can only come from a hand-written event that never went through
 * normalizeEvent — it is dropped rather than passed on as a module.
 */
function asModuleName(value: string): ModuleName | null {
  return (KNOWN_MODULES as string[]).includes(value) ? (value as ModuleName) : null;
}

function moduleAdminToken(): string | undefined {
  return process.env.MONOLITH_MODULE_ADMIN_TOKEN ?? process.env.MONOLITH_ADMIN_TOKEN;
}

function vectorAnchorUrl(pathname: string): URL | null {
  const base = process.env.VECTOR_ANCHOR_INTERNAL_URL;
  if (!base) return null;
  return moduleAdminUrl(
    base,
    pathname,
    process.env.MONOLITH_ALLOW_INSECURE_MODULE_HEALTH === "true",
  );
}

/**
 * The corpus size, read from the service that owns the ChromaDB client.
 * A second client on the same path contends on ChromaDB's SQLite store, so
 * the dashboard asks rather than opens its own.
 */
export async function readCorpusState(): Promise<CorpusState> {
  const base = process.env.VECTOR_ANCHOR_INTERNAL_URL;
  if (!base) {
    return { configured: false, reachable: false, documents: 0, quarantined: 0 };
  }
  const target = vectorAnchorUrl("/stats");
  const token = moduleAdminToken();
  if (!target || (token && !isBearerToken(token))) {
    return {
      configured: true,
      reachable: false,
      documents: 0,
      quarantined: 0,
      error: "unsafe configuration",
    };
  }
  try {
    const headers: Record<string, string> = {};
    if (token) headers.authorization = `Bearer ${token}`;
    const response = await fetch(target, {
      headers,
      cache: "no-store",
      signal: AbortSignal.timeout(2_000),
    });
    if (!response.ok) {
      return {
        configured: true,
        reachable: false,
        documents: 0,
        quarantined: 0,
        error: `status ${response.status}`,
      };
    }
    const body = (await response.json()) as Record<string, unknown>;
    return {
      configured: true,
      reachable: true,
      documents: Number(body.documents ?? 0),
      quarantined: Number(body.quarantined ?? 0),
    };
  } catch (error) {
    return {
      configured: true,
      reachable: false,
      documents: 0,
      quarantined: 0,
      error: error instanceof Error ? error.name : "request failed",
    };
  }
}

/**
 * Ask VectorAnchor to load its own demo corpus. The corpus lives with the
 * service's fixtures, so the dashboard holds no copy of it — it only says
 * which one it wants.
 */
export async function seedDemoCorpus(
  includeBait: boolean,
): Promise<{ added: number; total: number; bait: boolean }> {
  const target = vectorAnchorUrl("/admin/seed-demo");
  if (!target) throw new Error("VectorAnchor is not configured");
  const token = moduleAdminToken();
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (token) headers.authorization = `Bearer ${token}`;
  const response = await fetch(target, {
    method: "POST",
    headers,
    body: JSON.stringify({ include_bait: includeBait }),
    cache: "no-store",
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) {
    throw new Error(`VectorAnchor refused the seed (status ${response.status})`);
  }
  const body = (await response.json()) as Record<string, unknown>;
  return {
    added: Number(body.added ?? 0),
    total: Number(body.total ?? 0),
    bait: Boolean(body.bait),
  };
}

/** Clear the memory layer's frequency history and quarantine, keeping the corpus. */
export async function resetVectorDetection(): Promise<void> {
  const target = vectorAnchorUrl("/admin/reset-detection");
  if (!target) throw new Error("VectorAnchor is not configured");
  const token = moduleAdminToken();
  const headers: Record<string, string> = {};
  if (token) headers.authorization = `Bearer ${token}`;
  const response = await fetch(target, {
    method: "POST",
    headers,
    cache: "no-store",
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) {
    throw new Error(`VectorAnchor refused the reset (status ${response.status})`);
  }
}

/**
 * Look for the tool layer's binary on this machine.
 *
 * The launcher starts the MCP servers itself, so the binary has to exist on
 * the host that runs the agent. When the dashboard runs in a container that
 * host is not this filesystem, and saying "missing" would be a lie — so the
 * check reports that it could not look, and the page tells the operator to
 * build it where the agent actually runs.
 */
export function locateShieldBinary(): ShieldBinaryState {
  const hint = "cd mcp-shield && cargo build --release";
  const explicit = process.env.MONOLITH_MCP_SHIELD_BIN;
  if (explicit) {
    // The path comes from the environment, so the bundler cannot know what it
    // points at and would trace the whole project into the image to be safe.
    // The ignore pragma says "do not trace this one" — the file is looked up
    // at runtime, and it is a path on the operator's own machine either way.
    const path = isAbsolute(explicit)
      ? explicit
      : resolve(/*turbopackIgnore: true*/ process.cwd(), explicit);
    return { checked: true, found: existsSync(path), path: explicit, hint };
  }
  const repoRoot = resolve(process.cwd(), "..");
  const shieldRoot = join(repoRoot, "mcp-shield");
  if (!existsSync(shieldRoot)) {
    return { checked: false, found: false, path: null, hint };
  }
  for (const profile of ["release", "debug"]) {
    for (const name of ["mcp-shield", "mcp-shield.exe"]) {
      const candidate = join(shieldRoot, "target", profile, name);
      if (existsSync(candidate)) {
        return { checked: true, found: true, path: candidate, hint };
      }
    }
  }
  return { checked: true, found: false, path: null, hint };
}

/**
 * The sessions the ledger knows about, newest first.
 *
 * This is the read side of "is my agent connected yet?". The per-session
 * endpoint cannot answer it: an unknown session returns 200 with zero events,
 * which is indistinguishable from a connected-but-silent session.
 */
export async function listRecentSessions(
  tenantId: string,
  limit: number = DEFAULT_RECENT_SESSIONS,
): Promise<RecentSession[]> {
  const safeLimit = Math.max(1, Math.min(Math.trunc(limit), MAX_RECENT_SESSIONS));

  if (!process.env.DATABASE_URL) {
    const grouped = new Map<string, RecentSession>();
    for (const event of getMemoryEventsForTenant(tenantId)) {
      if (!event.session_id) continue;
      // The key uses a NUL separator because identityText() rejects control
      // characters, so NUL cannot appear inside either half. Without it,
      // agent "a" + session "bc" and agent "ab" + session "c" would collapse
      // into one group, and the two halves would not match the SQL path.
      const key = `${event.agent_id ?? ""}\u0000${event.session_id}`;
      const existing = grouped.get(key);
      const at = event.received_ms ?? event.timestamp_ms;
      const severity = event.severity;
      const moduleName = asModuleName(event.module);
      if (!existing) {
        grouped.set(key, {
          session_id: event.session_id,
          agent_id: event.agent_id ?? null,
          events: 1,
          modules: moduleName ? [moduleName] : [],
          worst_severity: severity,
          first_ms: at,
          last_ms: at,
        });
        continue;
      }
      existing.events += 1;
      if (moduleName && !existing.modules.includes(moduleName)) {
        existing.modules.push(moduleName);
      }
      if (SEVERITY_RANK[severity] > SEVERITY_RANK[existing.worst_severity]) {
        existing.worst_severity = severity;
      }
      existing.first_ms = existing.first_ms === null ? at : Math.min(existing.first_ms, at);
      existing.last_ms = existing.last_ms === null ? at : Math.max(existing.last_ms, at);
    }
    return [...grouped.values()]
      .sort((a, b) => (b.last_ms ?? 0) - (a.last_ms ?? 0))
      .slice(0, safeLimit);
  }

  return withTenantDb(tenantId, async (db) => {
    const result = await db.query<{
      session_id: string;
      agent_id: string | null;
      events: number;
      modules: string[];
      worst: number;
      first_ms: string | null;
      last_ms: string | null;
    }>(
      `select session_id, agent_id, count(*)::int as events,
              array_agg(distinct module) as modules,
              max(case severity when 'critical' then 2 when 'warning' then 1 else 0 end) as worst,
              (extract(epoch from min(received_at)) * 1000)::bigint as first_ms,
              (extract(epoch from max(received_at)) * 1000)::bigint as last_ms
         from monolith.security_events
        where tenant_id = $1 and session_id is not null
        group by session_id, agent_id
        order by last_ms desc
        limit $2`,
      [tenantId, safeLimit],
    );
    return result.rows.map((row) => ({
      session_id: row.session_id,
      agent_id: row.agent_id,
      events: Number(row.events ?? 0),
      modules: row.modules
        .map((m) => asModuleName(m))
        .filter((m): m is ModuleName => m !== null),
      worst_severity:
        Number(row.worst) >= 2 ? "critical" : Number(row.worst) === 1 ? "warning" : "info",
      first_ms: row.first_ms === null ? null : Number(row.first_ms),
      last_ms: row.last_ms === null ? null : Number(row.last_ms),
    }));
  });
}

function buildSteps(
  modules: OnboardingState["stack"]["modules"],
  corpus: CorpusState,
  shield: ShieldBinaryState,
  sessions: RecentSession[],
): OnboardingStep[] {
  const steps: OnboardingStep[] = [];

  const unreachable = modules.filter((m) => !m.reachable).map((m) => m.module);
  steps.push({
    id: "stack",
    label: "The stack is running",
    state: unreachable.length === 0 ? "ready" : "blocked",
    detail:
      unreachable.length === 0
        ? `All ${modules.length} layers are answering.`
        : `Not answering: ${unreachable.join(", ")}.`,
    action:
      unreachable.length === 0
        ? undefined
        : { kind: "command", label: "docker compose up -d --build --wait" },
  });

  if (!corpus.configured) {
    steps.push({
      id: "corpus",
      label: "The memory layer has a corpus",
      state: "unknown",
      detail: "VectorAnchor is not configured on this dashboard.",
    });
  } else if (!corpus.reachable) {
    steps.push({
      id: "corpus",
      label: "The memory layer has a corpus",
      state: "blocked",
      detail: corpus.error
        ? `VectorAnchor did not answer (${corpus.error}).`
        : "VectorAnchor did not answer.",
    });
  } else if (corpus.documents > 0) {
    steps.push({
      id: "corpus",
      label: "The memory layer has a corpus",
      state: "ready",
      detail: `${corpus.documents} document${corpus.documents === 1 ? "" : "s"} loaded.`,
    });
  } else {
    steps.push({
      id: "corpus",
      label: "The memory layer has a corpus",
      state: "todo",
      detail: "No documents yet — the agent would retrieve nothing.",
      action: { kind: "button", label: "Load the demo corpus", payload: "seed-corpus" },
    });
  }

  if (!shield.checked) {
    steps.push({
      id: "tool",
      label: "The tool layer is built",
      state: "unknown",
      detail:
        "The dashboard is not running on the machine that hosts your agent, so it cannot look for the binary.",
      action: { kind: "command", label: shield.hint },
    });
  } else if (shield.found) {
    steps.push({
      id: "tool",
      label: "The tool layer is built",
      state: "ready",
      detail: shield.path ? `Found at ${shield.path}.` : "Found.",
    });
  } else {
    steps.push({
      id: "tool",
      label: "The tool layer is built",
      state: "todo",
      detail: "The launcher starts the MCP servers itself, so it needs the binary.",
      action: { kind: "command", label: shield.hint },
    });
  }

  const newest = sessions[0];
  steps.push({
    id: "agent",
    label: "Your agent is connected",
    state: newest ? "ready" : "todo",
    detail: newest
      ? `Session ${newest.session_id} filed ${newest.events} event${newest.events === 1 ? "" : "s"}.`
      : "No session has been filed yet.",
    action: newest
      ? { kind: "link", label: "Open the session", payload: `/investigate?session=${encodeURIComponent(newest.session_id)}` }
      : { kind: "command", label: "python scripts/monolith_wrap.py --claude" },
  });

  const reporting = newest ? KNOWN_MODULES.filter((m) => newest.modules.includes(m)) : [];
  steps.push({
    id: "layers",
    label: "All three layers are reporting",
    state: reporting.length === KNOWN_MODULES.length ? "ready" : "todo",
    detail:
      reporting.length === KNOWN_MODULES.length
        ? `Reporting: ${reporting.join(", ")}.`
        : reporting.length === 0
          ? "Nothing has reported under this session yet."
          : `So far: ${reporting.join(", ")}.`,
  });

  return steps;
}

/** Everything the onboarding page needs, in one round trip. */
export async function readOnboardingState(tenantId: string): Promise<OnboardingState> {
  const [runtimes, corpus, sessions] = await Promise.all([
    probeModuleRuntimes(),
    readCorpusState(),
    listRecentSessions(tenantId, DEFAULT_RECENT_SESSIONS),
  ]);
  const modules = runtimes.map((runtime) => ({
    module: runtime.module,
    configured: runtime.configured,
    reachable: runtime.reachable,
    status: runtime.status,
  }));
  const shield = locateShieldBinary();
  return {
    generated_at_ms: Date.now(),
    tenant_id: tenantId,
    stack: {
      modules,
      reachable: modules.length > 0 && modules.every((m) => m.reachable),
    },
    corpus,
    shield_binary: shield,
    sessions,
    steps: buildSteps(modules, corpus, shield, sessions),
  };
}
