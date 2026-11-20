"use client";

import { useEffect, useState } from "react";
import OperatorBadge from "../components/OperatorBadge";
import { Rail } from "../components/Sidebar";
import ThemeToggle from "../components/ThemeToggle";

type Action = {
  id: string;
  repository: string;
  issue: number;
  agent_id: string;
  session_id: string;
  kind: "reply" | "add_label" | "remove_label";
  value: string;
  digest: string;
  status: string;
  reviewer: string | null;
  reviewed_at: string | null;
  expires_at: string;
  github_status: number | null;
  github_comment_id: string | null;
  session_revoked_at: string | null;
};

const labels = { reply: "Reply", add_label: "Add label", remove_label: "Remove label" };

async function listActions(before?: string, signal?: AbortSignal) {
  const query = before ? `?before=${encodeURIComponent(before)}` : "";
  const response = await fetch(`/api/github/triage${query}`, { cache: "no-store", signal });
  if (!response.ok) throw new Error("Could not load GitHub approvals.");
  return response.json() as Promise<{ actions: Action[]; can_review: boolean; next: string | null }>;
}

export default function TriagePage() {
  const [actions, setActions] = useState<Action[]>([]);
  const [canReview, setCanReview] = useState(false);
  const [next, setNext] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    listActions(undefined, controller.signal).then((data) => {
      setActions(data.actions);
      setCanReview(data.can_review);
      setNext(data.next);
    }).catch(() => {
      if (!controller.signal.aborted) setError("Could not load GitHub approvals.");
    }).finally(() => {
      if (!controller.signal.aborted) setBusy(false);
    });
    return () => controller.abort();
  }, []);

  async function load(before?: string) {
    setBusy(true);
    setError("");
    try {
      const data = await listActions(before);
      setActions((current) => before ? [...current, ...data.actions] : data.actions);
      setCanReview(data.can_review);
      setNext(data.next);
    } catch (failure) {
      setError((failure as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function review(action: Action, decision: "approve" | "deny" | "revoke_session") {
    setBusy(true);
    setError("");
    try {
      const response = await fetch(`/api/github/triage/${action.id}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ decision, digest: action.digest }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not record this decision.");
      setActions((current) => current.map((item) => {
        if (decision === "revoke_session") {
          return item.agent_id === action.agent_id && item.session_id === action.session_id
            ? { ...item, session_revoked_at: data.session.revoked_at } : item;
        }
        return item.id === action.id ? { ...item, ...data.action } : item;
      }));
    } catch (failure) {
      setError((failure as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="frame">
      <div className="app two-col">
        <Rail />
        <main className="main operations-page">
          <div className="topbar">
            <h1>GitHub approvals</h1>
            <div className="topbar-right">
              <button className="ghost-btn" disabled={busy} onClick={() => void load()}>Refresh</button>
              <OperatorBadge />
              <ThemeToggle />
            </div>
          </div>
          <div className="content-scroll operations-scroll" aria-busy={busy}>
            {error ? <p className="ops-error" role="alert">{error}</p> : null}
            {!busy && !error && actions.length === 0 ? <p>No GitHub actions have been proposed.</p> : null}
            {actions.map((action) => (
              <article className="card ops-table-card" key={action.id}>
                <div className="card-head">
                  <h2 className="card-title">{labels[action.kind]} · {action.repository} #{action.issue}</h2>
                  <span className="ops-state">{action.status}</span>
                </div>
                <div style={{ padding: "16px" }}>
                  <p className="card-meta">Agent {action.agent_id} · Session {action.session_id}</p>
                  <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", marginBlock: "12px" }}>{action.value}</pre>
                  {action.reviewer ? <p className="card-meta">Reviewed by {action.reviewer} · {action.reviewed_at}</p> : null}
                  {action.github_status ? <p className="card-meta">GitHub HTTP {action.github_status}{action.github_comment_id ? ` · Comment ${action.github_comment_id}` : ""}</p> : null}
                  {action.status === "pending" ? <p className="card-meta">Expires {action.expires_at}</p> : null}
                  {action.session_revoked_at ? <p className="card-meta">Session revoked {action.session_revoked_at}</p> : null}
                  {canReview ? (
                    <div className="topbar-right" style={{ justifyContent: "flex-start", marginTop: "12px" }}>
                      {action.status === "pending" && !action.session_revoked_at ? (
                        <>
                          <button className="ghost-btn" disabled={busy} onClick={() => void review(action, "approve")}>Approve and send</button>
                          <button className="ghost-btn" disabled={busy} onClick={() => void review(action, "deny")}>Deny</button>
                        </>
                      ) : null}
                      {!action.session_revoked_at ? <button className="ghost-btn" disabled={busy} onClick={() => void review(action, "revoke_session")}>Revoke session</button> : null}
                    </div>
                  ) : null}
                </div>
              </article>
            ))}
            {next ? <button className="ghost-btn" disabled={busy} onClick={() => void load(next)}>Load older actions</button> : null}
          </div>
        </main>
      </div>
    </div>
  );
}
