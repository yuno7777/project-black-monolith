"use client";

import { useEffect, useState } from "react";
import type { BusinessWorkspace } from "@/lib/business-store";
import OperatorBadge from "../components/OperatorBadge";
import { Rail } from "../components/Sidebar";
import ThemeToggle from "../components/ThemeToggle";
import { AgentDirectory } from "./AgentDirectory";
import { DecisionInbox, type Filter } from "./DecisionInbox";
import { PolicyPractice } from "./PolicyPractice";
import { businessRequest, type Save } from "./business-ui";
import "./business.css";

type Workspace = BusinessWorkspace & { operator: { role: string; teams: string[] } };
const sections = ["Decision inbox", "Agents", "Policies & practice", "Activity & reports"] as const;

export default function BusinessPage() {
  const [workspace, setWorkspace] = useState<Workspace | null>(null);
  const [section, setSection] = useState<(typeof sections)[number]>("Decision inbox");
  const [filter, setFilter] = useState<Filter>("pending");
  const [search, setSearch] = useState("");
  const [focusedId, setFocusedId] = useState("");
  const [revision, setRevision] = useState(0);
  const [loadingPage, setLoadingPage] = useState(false);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    const query = new URLSearchParams();
    if (filter !== "all") query.set("status", filter);
    if (focusedId) query.set("id", focusedId);
    businessRequest<Workspace>(`?${query}`, undefined, controller.signal).then(setWorkspace).catch((failure: Error) => {
      if (!controller.signal.aborted) { setError(failure.message); setWorkspace(null); }
    }).finally(() => { if (!controller.signal.aborted) setBusy(false); });
    return () => controller.abort();
  }, [filter, focusedId, revision]);

  function refresh() {
    setBusy(true); setError(""); setNotice(""); setRevision((value) => value + 1);
  }

  async function loadOlder(list: "decisions" | "activity") {
    if (!workspace || busy || loadingPage) return;
    const cursor = list === "decisions" ? workspace.next : workspace.activityNext;
    if (!cursor) return;
    setLoadingPage(true); setError("");
    try {
      const query = new URLSearchParams();
      if (filter !== "all") query.set("status", filter);
      if (focusedId) query.set("id", focusedId);
      query.set(list === "decisions" ? "before" : "activityBefore", cursor);
      const page = await businessRequest<Workspace>(`?${query}`);
      setWorkspace((current) => current !== workspace ? current : list === "decisions"
        ? { ...current, decisions: [...current.decisions, ...page.decisions], next: page.next }
        : { ...current, activity: [...current.activity, ...page.activity], activityNext: page.activityNext });
    } catch (failure) { setError((failure as Error).message); }
    finally { setLoadingPage(false); }
  }
  const save: Save = async (path, body, message) => {
    setBusy(true); setError(""); setNotice("");
    let saved = false;
    try { await businessRequest(path, body); saved = true; setNotice(message); }
    catch (failure) { setError((failure as Error).message); }
    setRevision((value) => value + 1);
    return saved;
  };

  function openCases(status: Filter, query = "") {
    const changed = status !== filter || query !== focusedId;
    if (changed) { setBusy(true); setWorkspace(null); setError(""); }
    setFilter(status); setFocusedId(query); setSearch(""); setSection("Decision inbox");
  }

  return <div className="frame"><div className="app two-col"><Rail />
    <main className="main operations-page biz-page">
      <div className="topbar"><h1>Business workspace</h1><div className="topbar-right">
        <button className="ghost-btn" disabled={busy} onClick={() => void refresh()}>Refresh</button><OperatorBadge /><ThemeToggle />
      </div></div>
      <nav aria-label="Business workspace" className="biz-nav">{sections.map((name) => <button key={name} aria-current={section === name ? "page" : undefined} onClick={() => { setSection(name); setNotice(""); }}>{name}</button>)}</nav>
      <div className="content-scroll operations-scroll biz-content" aria-busy={busy || loadingPage}>
        {error && <p className="ops-error" role="alert">{error}</p>}{notice && <p role="status" className="biz-notice">{notice}</p>}
        {busy && !workspace && <p>Loading workspace…</p>}
        {workspace && <>
          {section === "Decision inbox" && <>
            {focusedId && <div className="biz-heading"><span>Decision {focusedId}</span><button className="ghost-btn" onClick={() => openCases("all")}>Clear selection</button></div>}
            <DecisionInbox decisions={workspace.decisions} operator={workspace.operator} filter={filter} setFilter={openCases} search={search} setSearch={setSearch} busy={busy || loadingPage} save={save} />
            {workspace.next && <button className="ghost-btn" disabled={busy || loadingPage} onClick={() => void loadOlder("decisions")}>Load older decisions</button>}
          </>}
          {section === "Agents" && <AgentDirectory agents={workspace.agents} admin={workspace.operator.role === "admin"} busy={busy} save={save} />}
          {section === "Policies & practice" && <PolicyPractice key={JSON.stringify(workspace.policy)} policy={workspace.policy} admin={workspace.operator.role === "admin"} busy={busy} save={save} />}
          {section === "Activity & reports" && <>
            <h2>Decision outcomes</h2>
            <div className="biz-metrics">{([
              ["pending", "Awaiting review"], ["overdue", "Past deadline"], ["denied", "Denied"],
              ["changes_requested", "Changes requested"], ["uncertain", "Uncertain outcome"], ["succeeded", "Confirmed"],
            ] as const).map(([status, label]) => <button key={status} onClick={() => openCases(status === "overdue" ? "expired" : status)}><span>{label}</span><strong>{workspace.report[status]}</strong></button>)}</div>
            <p>Average review time · {workspace.report.mean_review_seconds == null ? "No reviews yet" : `${Math.round(workspace.report.mean_review_seconds / 60)} min`}</p>
            <h2>Recent activity</h2>
            {workspace.activity.length === 0 ? <p className="biz-empty">No business activity has been recorded.</p> : <ol className="biz-timeline">{workspace.activity.map((item) => <li key={item.id}>
              <strong>{item.event.replaceAll("_", " ")}</strong><span>{item.actor} · {new Date(item.created_at).toLocaleString()}</span>
              {item.note && <p>{item.note}</p>}
              {item.decision_id && <button className="ghost-btn" onClick={() => openCases("all", item.decision_id!)}>View decision</button>}
            </li>)}</ol>}
            {workspace.activityNext && <button className="ghost-btn" disabled={busy || loadingPage} onClick={() => void loadOlder("activity")}>Load older activity</button>}
          </>}
        </>}
      </div>
    </main></div></div>;
}
