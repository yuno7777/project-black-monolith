"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { Rail } from "../components/Sidebar";
import ThemeToggle from "../components/ThemeToggle";
import OperatorBadge from "../components/OperatorBadge";
import { IconCheck, IconPlug, ModuleGlyph } from "../components/Icons";
import { MODULE_LABELS } from "@/lib/types";

type StepState = "ready" | "todo" | "blocked" | "unknown";

type Step = {
  id: string;
  label: string;
  state: StepState;
  detail: string;
  action?: { kind: "command" | "button" | "link"; label: string; payload?: string };
};

type Session = {
  session_id: string;
  agent_id: string | null;
  events: number;
  modules: string[];
  worst_severity: string;
  last_ms: number | null;
};

type State = {
  generated_at_ms: number;
  tenant_id: string;
  role: string;
  stack: {
    reachable: boolean;
    modules: Array<{ module: string; configured: boolean; reachable: boolean }>;
  };
  corpus: { configured: boolean; reachable: boolean; documents: number; quarantined: number };
  shield_binary: { checked: boolean; found: boolean; path: string | null; hint: string };
  sessions: Session[];
  steps: Step[];
};

const START_COMMAND = "python scripts/monolith_wrap.py --claude";

/**
 * The prompts an operator types into their own agent, one per layer.
 *
 * The wording matters: the memory layer's prompts steer the model into
 * issuing exactly the queries the bait document ranks for, and the reasoning
 * layer's prompt is framed so the model quotes the string back rather than
 * refusing to mention it. The key below is AWS's own published example
 * credential — it is in the AWS documentation precisely so that scanners
 * recognise it, and it is not a credential to anything.
 */
const PROMPTS: Array<{
  layer: string;
  module: string;
  title: string;
  lines: string[];
  expect: string;
}> = [
  {
    layer: "Memory",
    module: "vector-anchor",
    title: "Make the agent retrieve",
    lines: [
      "Use the retrieve tool with exactly this query:",
      "  how do I prune tomato plants in my garden",
      "  what is a red giant star in a galaxy",
      "  how long should I boil pasta noodles",
      "  how much emergency fund and savings should I budget",
    ],
    expect:
      "One query per turn. The fourth is the one that trips the memory layer — a bait document that answers every question gets withheld, and the agent is told how many documents were withheld.",
  },
  {
    layer: "Reasoning",
    module: "trace-audit",
    title: "Make the model quote a credential",
    lines: [
      "I'm debugging an AWS SDK call that keeps failing. My access key id is",
      "AKIAIOSFODNN7EXAMPLE",
      "and STS says my email is dba@example-internal.io.",
      "Summarise what could be wrong.",
    ],
    expect:
      "The credential is redacted in the stream before the agent reads it. The agent sees [REDACTED:…] in its place; the ledger keeps the finding.",
  },
  {
    layer: "Tool",
    module: "mcp-shield",
    title: "Give the tool layer something to protect",
    lines: [
      "Every MCP server your agent would have started is started through",
      "MCP-Shield instead. A tool whose schema changes after you approved it",
      "is flagged, and by default the approved schema is handed back.",
      "",
      "To see that on its own:  cd mcp-shield && bash fixtures/run_demo.sh",
    ],
    expect:
      "A changed schema is reported as schema_mismatch, and in enforce mode the agent still receives the shape you approved.",
  },
];

function ago(value: number | null): string {
  if (!value) return "—";
  const seconds = Math.max(0, Math.round((Date.now() - value) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

const STATE_LABEL: Record<StepState, string> = {
  ready: "Ready",
  todo: "To do",
  blocked: "Blocked",
  unknown: "Not checked",
};

export default function OnboardingClient() {
  const [data, setData] = useState<State | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  const load = useCallback(async () => {
    setRefreshing(true);
    try {
      const response = await fetch("/api/onboarding", { cache: "no-store" });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error ?? "the onboarding request failed");
      setData(body);
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "the onboarding request failed");
    } finally {
      setRefreshing(false);
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    const timer = setInterval(load, 10_000);
    return () => clearInterval(timer);
  }, [load]);

  const runAction = useCallback(
    async (action: string) => {
      setBusy(action);
      setError(null);
      try {
        const response = await fetch("/api/onboarding", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action }),
        });
        const body = await response.json();
        if (!response.ok) throw new Error(body.error ?? "the action failed");
        await load();
      } catch (reason) {
        setError(reason instanceof Error ? reason.message : "the action failed");
      } finally {
        setBusy(null);
      }
    },
    [load],
  );

  const copy = useCallback(async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      setTimeout(() => setCopied((current) => (current === key ? null : current)), 1_600);
    } catch {
      setError("the browser refused the clipboard");
    }
  }, []);

  const canSeed = data?.role === "admin";

  return (
    <div className="frame">
      <div className="app two-col">
        <Rail />
        <main className="main operations-page">
          <div className="topbar">
            <div>
              <h1>Connect your agent</h1>
              <div className="crumb">One session · three layers · one ledger</div>
            </div>
            <div className="topbar-right">
              <button className="ghost-btn" onClick={() => void load()} disabled={refreshing}>
                {refreshing ? "Refreshing…" : "Refresh"}
              </button>
              <OperatorBadge />
              <ThemeToggle />
            </div>
          </div>

          <div className="content-scroll operations-scroll">
            {error ? <div className="ops-error">{error}</div> : null}

            <section className="onb-steps">
              {loading ? (
                <div className="ops-empty">Checking the stack…</div>
              ) : (
                (data?.steps ?? []).map((step, index) => (
                  <article className={`onb-step onb-${step.state}`} key={step.id}>
                    <span className="onb-step-n num">{index + 1}</span>
                    <div className="onb-step-main">
                      <div className="onb-step-head">
                        <strong>{step.label}</strong>
                        <span className="onb-step-state">{STATE_LABEL[step.state]}</span>
                      </div>
                      <span className="onb-step-detail">{step.detail}</span>
                      {step.action?.kind === "button" ? (
                        <button
                          className="ghost-btn onb-btn"
                          disabled={!canSeed || busy !== null}
                          onClick={() => void runAction(step.action?.payload ?? "")}
                          title={
                            canSeed
                              ? undefined
                              : "Loading the corpus changes what the memory layer sees, so it is an administrator's action."
                          }
                        >
                          {busy === step.action?.payload
                            ? "Working…"
                            : canSeed
                              ? step.action.label
                              : `${step.action.label} (admin only)`}
                        </button>
                      ) : null}
                      {step.action?.kind === "command" ? (
                        <div className="onb-cmd-row">
                          <code className="onb-cmd">{step.action.label}</code>
                          <button
                            className="iconbtn"
                            onClick={() => void copy(step.action?.label ?? "", step.id)}
                            title="Copy"
                            aria-label={`Copy ${step.action.label}`}
                          >
                            {copied === step.id ? <IconCheck /> : <IconPlug size={15} />}
                          </button>
                        </div>
                      ) : null}
                      {step.action?.kind === "link" ? (
                        <Link className="onb-link" href={step.action.payload ?? "/"}>
                          {step.action.label} →
                        </Link>
                      ) : null}
                    </div>
                  </article>
                ))
              )}
            </section>

            <section className="card onb-card">
              <div className="card-head">
                <div>
                  <span className="card-title">Start your agent</span>
                  <div className="card-meta">from the repository root</div>
                </div>
              </div>
              <div className="onb-cmd-row">
                <code className="onb-cmd">{START_COMMAND}</code>
                <button
                  className="iconbtn"
                  onClick={() => void copy(START_COMMAND, "start")}
                  title="Copy"
                  aria-label="Copy the start command"
                >
                  {copied === "start" ? <IconCheck /> : <IconPlug size={15} />}
                </button>
              </div>
              <p className="onb-note">
                The launcher reads the repository&apos;s own <code>.env</code>, so this command
                carries no secret and there is nothing for you to paste in. Your agent&apos;s
                own credential is forwarded upstream untouched — the gateway holds no key of
                its own.
              </p>
            </section>

            <section className="card onb-card">
              <div className="card-head">
                <div>
                  <span className="card-title">What to type into the agent</span>
                  <div className="card-meta">one prompt per layer · all local fixtures</div>
                </div>
              </div>
              <div className="onb-prompts">
                {PROMPTS.map((prompt) => (
                  <article className="onb-prompt" key={prompt.module}>
                    <div className="onb-prompt-head">
                      <span className="onb-prompt-layer">
                        <ModuleGlyph module={prompt.module} size={16} />
                        {prompt.layer}
                      </span>
                      <strong>{prompt.title}</strong>
                    </div>
                    <pre className="onb-prompt-body">{prompt.lines.join("\n")}</pre>
                    <p className="onb-note">{prompt.expect}</p>
                  </article>
                ))}
              </div>
            </section>

            <section className="card onb-card">
              <div className="card-head">
                <div>
                  <span className="card-title">Recent sessions</span>
                  <div className="card-meta">what the ledger has filed</div>
                </div>
                <span className="card-meta">
                  {data ? `${data.sessions.length} in this tenant` : "—"}
                </span>
              </div>
              {data?.sessions.length ? (
                <div className="onb-sessions">
                  {data.sessions.map((session) => (
                    <article className="onb-session" key={`${session.agent_id ?? ""}-${session.session_id}`}>
                      <div className="onb-session-main">
                        <code className="mono-id">{session.session_id}</code>
                        <span className="onb-session-meta">
                          {session.agent_id ?? "unknown agent"} · {session.events} event
                          {session.events === 1 ? "" : "s"} · {ago(session.last_ms)}
                        </span>
                      </div>
                      <div className="onb-session-modules">
                        {session.modules.map((module) => (
                          <span className="chip" key={module} style={{ ["--accent-mod" as string]: "var(--ink-dim)" }}>
                            <ModuleGlyph module={module} size={14} />
                            {MODULE_LABELS[module] ?? module}
                          </span>
                        ))}
                      </div>
                      <Link
                        className="onb-link"
                        href={`/investigate?session=${encodeURIComponent(session.session_id)}`}
                      >
                        Open →
                      </Link>
                    </article>
                  ))}
                </div>
              ) : (
                <div className="ops-empty">
                  No session yet. Start the gateway and the session appears here within a few
                  seconds.
                </div>
              )}
            </section>
          </div>
        </main>
      </div>
    </div>
  );
}
