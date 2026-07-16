// The shared Project Black Monolith event shape emitted by all three modules
// (mcp-shield, VectorAnchor, TraceAudit). The dashboard consumes this shape
// uniformly regardless of which module produced the event.

export type Severity = "info" | "warning" | "critical";

export type ModuleName = "mcp-shield" | "vector-anchor" | "trace-audit";

export interface MonolithEvent {
  event_id?: string;
  schema_version?: 1 | 2;
  timestamp_ms: number;
  module: string;
  event_type: string;
  severity: Severity;
  details: Record<string, unknown>;
  // Assigned by the dashboard on ingest (monotonic, for stable React keys and
  // newest-first ordering even when timestamps collide).
  seq?: number;
  // Wall-clock time the dashboard received the event (ms since epoch).
  received_ms?: number;
  agent_id?: string;
  session_id?: string;
  trace_id?: string;
  correlation_id?: string;
  resource_type?: string;
  resource_id?: string;
  outcome?: string;
  policy_version?: string;
  source?: string;
}

// ---------------------------------------------------------------------------
// Incident lifecycle. Triage is human judgement *about* an event; it is stored
// and typed separately from the event, which stays immutable evidence.

export type IncidentStatus = "new" | "acknowledged" | "resolved";

export type Resolution = "true_positive" | "false_positive" | "benign" | "duplicate";

export interface Triage {
  status: IncidentStatus;
  assignee?: string;
  note?: string;
  resolution?: Resolution;
  updated_ms: number;
  updated_by: string;
}

/** A ledger event joined with its triage state (absent until first triaged). */
export interface Incident extends MonolithEvent {
  event_id: string;
  triage?: Triage;
}

export interface AuditEntry {
  audit_id: number;
  at_ms: number;
  actor: string;
  from_status?: IncidentStatus;
  to_status: IncidentStatus;
  assignee?: string;
  resolution?: Resolution;
  note?: string;
}

/** One defense layer's contribution to a single agent session. */
export interface SessionLayer {
  module: string;
  events: number;
  worst: Severity;
}

/** An agent session as seen across all three layers at once. */
export interface SessionView {
  session_id: string;
  agent_id?: string;
  layers: SessionLayer[];
  total: number;
  cross_layer: boolean;
  first_ms: number;
  last_ms: number;
}

export const INCIDENT_STATUSES: IncidentStatus[] = ["new", "acknowledged", "resolved"];

export const STATUS_LABELS: Record<IncidentStatus, string> = {
  new: "New",
  acknowledged: "Acknowledged",
  resolved: "Resolved",
};

export const RESOLUTIONS: Resolution[] = [
  "true_positive",
  "false_positive",
  "benign",
  "duplicate",
];

export const RESOLUTION_LABELS: Record<Resolution, string> = {
  true_positive: "True positive",
  false_positive: "False positive",
  benign: "Benign",
  duplicate: "Duplicate",
};

export const KNOWN_MODULES: ModuleName[] = [
  "mcp-shield",
  "vector-anchor",
  "trace-audit",
];

export const MODULE_LABELS: Record<string, string> = {
  "mcp-shield": "MCP-Shield",
  "vector-anchor": "VectorAnchor",
  "trace-audit": "TraceAudit",
};

export const MODULE_LAYER: Record<string, string> = {
  "mcp-shield": "Tool layer",
  "vector-anchor": "Memory layer",
  "trace-audit": "Reasoning layer",
};

export const MODULE_ACCENT: Record<string, string> = {
  "mcp-shield": "var(--mod-mcp)",
  "vector-anchor": "var(--mod-vector)",
  "trace-audit": "var(--mod-trace)",
};
