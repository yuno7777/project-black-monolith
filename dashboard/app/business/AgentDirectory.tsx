import { useState } from "react";
import type { BusinessWorkspace } from "@/lib/business-store";
import type { BusinessAction } from "@/lib/business-policy";
import { actionNames, type Save } from "./business-ui";

type Agent = BusinessWorkspace["agents"][number];
const kinds = Object.keys(actionNames) as BusinessAction["kind"][];

function AgentForm({ agent, busy, save, close }: { agent?: Agent; busy: boolean; save: Save; close: () => void }) {
  return <form className="biz-panel biz-form" onSubmit={async (event) => {
    event.preventDefault();
    const fields = new FormData(event.currentTarget);
    const saved = await save("/agents", {
      agentId: fields.get("agentId"), owner: fields.get("owner"),
      allowedKinds: fields.getAll("kind"), paused: fields.has("paused"), practiceOnly: fields.has("practiceOnly"),
    }, "Agent permissions saved.");
    if (saved) close();
  }}>
    <h2>{agent ? "Edit permissions" : "Add agent"}</h2>
    <div className="biz-grid">
      <label>Agent ID<input name="agentId" required readOnly={Boolean(agent)} defaultValue={agent?.agent_id} placeholder="support-agent" /></label>
      <label>Owner<input name="owner" required defaultValue={agent?.owner} placeholder="Customer support" /></label>
    </div>
    <fieldset><legend>Permitted actions</legend>{kinds.map((kind) => <label className="biz-check" key={kind}>
      <input type="checkbox" name="kind" value={kind} defaultChecked={agent?.allowed_kinds.includes(kind)} />{actionNames[kind]}
    </label>)}</fieldset>
    <label className="biz-check"><input name="practiceOnly" type="checkbox" defaultChecked={agent?.practice_only ?? true} />Practice only</label>
    <p>Clear practice only to let this agent submit actions for approval.</p>
    <label className="biz-check"><input name="paused" type="checkbox" defaultChecked={agent?.paused} />Pause agent</label>
    <div className="biz-buttons"><button className="biz-primary" disabled={busy}>Save agent</button><button className="ghost-btn" type="button" onClick={close}>Cancel</button></div>
  </form>;
}

export function AgentDirectory({ agents, admin, busy, save }: { agents: Agent[]; admin: boolean; busy: boolean; save: Save }) {
  const [editing, setEditing] = useState<Agent | "new" | null>(null);
  return <>
    <div className="biz-heading"><h2>Agent directory</h2>{admin && <button className="ghost-btn" onClick={() => setEditing("new")}>Add agent</button>}</div>
    {editing && <AgentForm key={editing === "new" ? "" : editing.agent_id} agent={editing === "new" ? undefined : editing} busy={busy} save={save} close={() => setEditing(null)} />}
    {agents.length === 0 && <p className="biz-empty">No business agents have been registered.</p>}
    {agents.map((agent) => <article className="biz-panel" key={agent.agent_id}>
      <div className="biz-heading"><h3>{agent.agent_id}</h3><span className="ops-state">{agent.paused ? "Paused" : agent.practice_only ? "Practice only" : "Live proposals"}</span></div>
      <dl className="biz-fields"><div><dt>Owner</dt><dd>{agent.owner}</dd></div><div><dt>Permitted actions</dt><dd>{agent.allowed_kinds.map((kind) => actionNames[kind]).join(", ") || "None"}</dd></div>
        <div><dt>Last activity</dt><dd>{agent.last_activity ? new Date(agent.last_activity).toLocaleString() : "No activity yet"}</dd></div></dl>
      {admin && <button className="ghost-btn" onClick={() => setEditing(agent)}>Edit permissions</button>}
    </article>)}
  </>;
}
