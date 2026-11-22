import { useState } from "react";
import type { BusinessWorkspace } from "@/lib/business-store";
import { actionNames, ActionPreview, type Save } from "./business-ui";

export type Filter = "all" | "expired" | "pending" | "denied" | "changes_requested" | "uncertain" | "succeeded";
const options: Record<Filter, string> = {
  all: "All decisions", pending: "Awaiting review", expired: "Past deadline",
  uncertain: "Uncertain outcome", denied: "Denied", changes_requested: "Changes requested", succeeded: "Confirmed",
};
type Decision = BusinessWorkspace["decisions"][number];
type Choice = "approve" | "deny" | "request_changes" | "confirm" | "not_applied";

function DecisionReview({ item, busy, save, canReview }: { item: Decision; busy: boolean; save: Save; canReview: boolean }) {
  const [note, setNote] = useState("");
  const [choice, setChoice] = useState<Choice | null>(null);
  const confirming = choice === "confirm" || choice === "not_applied";
  const requiresNote = confirming || choice === "request_changes";
  const label: Record<Choice, string> = { approve: "Approve and send", deny: "Deny", request_changes: "Request changes", confirm: "Confirm applied", not_applied: "Confirm not applied" };
  const actions: Choice[] = item.status === "pending" ? ["approve", "deny", "request_changes"] : item.status === "uncertain" ? ["confirm", "not_applied"] : [];
  return <article className="biz-panel">
    <div className="biz-heading"><h3>{actionNames[item.action.kind]} · {item.case_id}</h3><span className="ops-state">{item.status.replaceAll("_", " ")}</span></div>
    <p>{item.agent_id} · {item.reviewer_team} review · {new Date(item.created_at).toLocaleString()}</p>
    <ActionPreview action={item.action} />
    <p>{item.reason}</p>
    {item.status === "pending" && <p>Review by {new Date(item.expires_at).toLocaleString()}</p>}
    {item.reference && <p>Confirmation reference <code>{item.reference}</code></p>}
    {item.reviewer && <p>Reviewed by {item.reviewer}</p>}
    <details><summary>Action details</summary><dl className="biz-fields"><div><dt>Decision ID</dt><dd>{item.id}</dd></div><div><dt>Session</dt><dd>{item.session_id}</dd></div><div><dt>Content digest</dt><dd>{item.digest}</dd></div></dl></details>
    {canReview && actions.length > 0 && <div className="biz-buttons">{actions.map((value) => <button key={value} className="ghost-btn" disabled={busy} onClick={() => { setChoice(value); setNote(""); }}>{label[value]}</button>)}</div>}
    {canReview && choice && actions.includes(choice) && <form className="biz-form biz-confirm" onSubmit={async (event) => {
      event.preventDefault();
      const saved = await save("/decisions", { id: item.id, digest: item.digest, decision: choice, ...(note.trim() ? { note: note.trim() } : {}) }, "Decision recorded.");
      if (saved) { setChoice(null); setNote(""); }
    }}>
      <h4>{label[choice]}</h4>
      {choice === "approve" && <p>Confirm the exact action shown above will be sent to the configured connector.</p>}
      {choice === "request_changes" && <p>The agent must submit a revised proposal for a new review.</p>}
      {confirming && <p>Check the connected system. This records your finding without sending the action again.</p>}
      {choice !== "approve" && <label>{confirming ? "Verification evidence" : choice === "request_changes" ? "Requested changes" : "Decision note (optional)"}<textarea maxLength={1000} value={note} required={requiresNote} onChange={(event) => setNote(event.target.value)} /></label>}
      <div className="biz-buttons"><button className="biz-primary" disabled={busy || (requiresNote && !note.trim())}>Confirm decision</button><button type="button" className="ghost-btn" onClick={() => setChoice(null)}>Cancel</button></div>
    </form>}
  </article>;
}

export function DecisionInbox({ decisions, operator, filter, setFilter, search, setSearch, busy, save }: {
  decisions: Decision[]; operator: { role: string; teams: string[] }; filter: Filter; setFilter: (v: Filter) => void;
  search: string; setSearch: (value: string) => void; busy: boolean; save: Save;
}) {
  const visible = decisions.filter((item) => {
    return [item.id, item.case_id, item.agent_id, item.reviewer_team, item.reference].some((value) => value?.toLowerCase().includes(search.toLowerCase().trim()));
  });
  return <><div className="biz-panel biz-grid">
    <label>Status<select disabled={busy} value={filter} onChange={(event) => setFilter(event.target.value as Filter)}>{Object.entries(options).map(([key, value]) => <option key={key} value={key}>{value}</option>)}</select></label>
    <label>Find a decision<input type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Case, agent, team, or decision ID" /></label>
  </div>
    {visible.length === 0 && <p className="biz-empty">{decisions.length ? "No loaded decisions match your filters." : "No business actions match this view."}</p>}
    {visible.map((item) => <DecisionReview key={item.id + item.status} item={item} busy={busy} save={save}
      canReview={operator.role !== "viewer" && operator.teams.includes(item.reviewer_team)} />)}
  </>;
}
