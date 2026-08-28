// The shared Project Black Monolith event shape emitted by all three modules
// (mcp-shield, VectorAnchor, TraceAudit). The dashboard consumes this shape
// uniformly regardless of which module produced the event.
//
// WHAT THIS FILE IS
// -----------------
// The TypeScript side of the shared event contract. It defines the types the
// whole dashboard is written against (events, incidents, sessions, labels)
// plus the small lookup tables the UI uses for labels/colors.
//
// The same contract exists as:
//   - JSON Schema:  contracts/schemas/event-envelope.v2.schema.json (the
//     canonical, machine-checked version)
//   - Python:       python-common/monolith_events/events.py
//   - Rust:         mcp-shield/src/events.rs
// contracts/check_contracts.py keeps the schema valid; the modules' tests
// keep the implementations in sync with it.
//
// The correlation fields (agent_id/session_id/trace_id/correlation_id) are
// OPTIONAL because modules omit them when unknown — absence means "nobody told
// us", not "belongs to nothing".

export type Severity = "info" | "warning" | "critical";

export type ModuleName = "mcp-shield" | "vector-anchor" | "trace-audit";

export interface MonolithEvent {
  event_id: string;
  schema_version: 1 | 2;
  timestamp_ms: number;
  module: string;
  event_type: string;
  severity: Severity;
  details: Record<string, unknown>;
  tenant_id: string;
  // Wall-clock time the dashboard received the event (ms since epoch).
  // Added server-side at ingest; absent on events that haven't been ingested
  // yet. The feed sorts by this so ordering reflects arrival, not clock skew.
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
// The event (security_events row) is never mutated by triage — the judgement
// lives in incident_triage + incident_audit tables.

export type IncidentStatus = "new" | "acknowledged" | "resolved";

export type Resolution = "true_positive" | "false_positive" | "benign" | "duplicate";

export interface Triage {
  status: IncidentStatus;
  assignee?: string;
  note?: string;
  resolution?: Resolution;
  updated_ms: number;
  updated_by: string; // always derived from the credential, never the request
}

/** A ledger event joined with its triage state (absent until first triaged).
 * The incident-store turns DB rows into this shape. */
export interface Incident extends MonolithEvent {
  event_id: string;
  triage?: Triage;
}

/** One entry of the append-only incident_audit table. */
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

/** An agent session as seen across all three layers at once.
 * Produced by incident-store.sessionForEvent(); this is the cross-layer
 * correlation payoff — one module firing is a detection, several layers in
 * one session is a compromised agent. */
export interface SessionView {
  tenant_id: string;
  session_id: string;
  agent_id: string;
  layers: SessionLayer[];
  total: number;
  cross_layer: boolean;
  first_ms: number;
  last_ms: number;
}

// --- UI lookup tables used by pages/components -----------------------------

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

// Theme-aware accent colors (CSS variables, so they follow dark/light mode).
export const MODULE_ACCENT: Record<string, string> = {
  "mcp-shield": "var(--mod-mcp)",
  "vector-anchor": "var(--mod-vector)",
  "trace-audit": "var(--mod-trace)",
};
