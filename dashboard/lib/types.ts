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
