// The shared Project Black Monolith event shape emitted by all three modules
// (mcp-shield, VectorAnchor, TraceAudit). The dashboard consumes this shape
// uniformly regardless of which module produced the event.

export type Severity = "info" | "warning" | "critical";

export type ModuleName = "mcp-shield" | "vector-anchor" | "trace-audit";

export interface MonolithEvent {
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
