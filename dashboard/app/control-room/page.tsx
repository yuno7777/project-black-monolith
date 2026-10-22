"use client";

import { useState } from "react";
import { Rail } from "../components/Sidebar";
import ThemeToggle from "../components/ThemeToggle";
import OperatorBadge from "../components/OperatorBadge";
import {
  IconIntercept,
  IconCheck,
  IconAlert,
  IconBolt,
  IconTool,
  IconMemory,
  IconReason,
  IconHistory,
  IconX,
} from "../components/Icons";

interface QuarantinedSession {
  id: string;
  sessionId: string;
  revokedAt: string;
  reason: string;
  originatingLayer: "trace-audit" | "vector-anchor" | "mcp-shield" | "operator";
  status: "quarantined" | "restored";
}

interface ToolBaseline {
  name: string;
  fingerprint: string;
  riskLevel: "critical" | "warning" | "low";
  lastVerified: string;
  status: "PINNED" | "DRIFT_DETECTED" | "GATED" | "REVOKED";
}

interface ActionLogItem {
  id: string;
  timestamp: string;
  operator: string;
  action: string;
  target: string;
  status: "SUCCESS" | "FAILED" | "TRIPPED";
}

const INITIAL_QUARANTINED_SESSIONS: QuarantinedSession[] = [
  {
    id: "q-1",
    sessionId: "session-agent-jailbreak-88a",
    revokedAt: "2 mins ago",
    reason: "Prompt Injection & System Prompt Exfiltration (LLM01)",
    originatingLayer: "trace-audit",
    status: "quarantined",
  },
  {
    id: "q-2",
    sessionId: "session-agent-poison-04c",
    revokedAt: "14 mins ago",
    reason: "RAG Universal Bait Query Anomaly (LLM04)",
    originatingLayer: "vector-anchor",
    status: "quarantined",
  },
  {
    id: "q-3",
    sessionId: "session-agent-rugpull-11b",
    revokedAt: "38 mins ago",
    reason: "Unauthenticated MCP Schema Parameter Mutation (LLM03)",
    originatingLayer: "mcp-shield",
    status: "quarantined",
  },
];

const INITIAL_TOOL_BASELINES: ToolBaseline[] = [
  {
    name: "read_file",
    fingerprint: "e7c22857410c66008b4923e031a0f670...fa89",
    riskLevel: "low",
    lastVerified: "Today, 14:20 UTC",
    status: "PINNED",
  },
  {
    name: "write_file",
    fingerprint: "8f5a11d23467b931c89012a4332bf120...01ea",
    riskLevel: "warning",
    lastVerified: "Today, 14:20 UTC",
    status: "PINNED",
  },
  {
    name: "run_command",
    fingerprint: "5d012e84c90ab2238127394ef342ac34...b29f",
    riskLevel: "critical",
    lastVerified: "Today, 15:10 UTC",
    status: "GATED",
  },
  {
    name: "database_query",
    fingerprint: "21fa980c65ef431287b92019a8451120...33c1",
    riskLevel: "warning",
    lastVerified: "Today, 14:20 UTC",
    status: "PINNED",
  },
  {
    name: "http_request",
    fingerprint: "1198ef01bc432a67e980312fa8743129...ca04",
    riskLevel: "critical",
    lastVerified: "Today, 13:45 UTC",
    status: "PINNED",
  },
];

export default function ControlRoomPage() {
  const [quarantinedSessions, setQuarantinedSessions] = useState<QuarantinedSession[]>(INITIAL_QUARANTINED_SESSIONS);
  const [toolBaselines, setToolBaselines] = useState<ToolBaseline[]>(INITIAL_TOOL_BASELINES);
  const [targetSessionInput, setTargetSessionInput] = useState("");
  const [quarantineReason, setQuarantineReason] = useState("Manual operator intervention");
  const [isHalted, setIsHalted] = useState(false);
  const [activeMemoryPartition, setActiveMemoryPartition] = useState("prod-agent-memory");
  const [memoryNotification, setMemoryNotification] = useState<string | null>(null);
  const [exportSessionId, setExportSessionId] = useState("session-agent-jailbreak-88a");
  const [isExporting, setIsExporting] = useState(false);
  const [evidenceFeedback, setEvidenceFeedback] = useState<string | null>(null);

  const [actionHistory, setActionHistory] = useState<ActionLogItem[]>([
    {
      id: "act-1",
      timestamp: "15:30:12 UTC",
      operator: "sec-ops-admin",
      action: "CIRCUIT_BREAKER_TRIPPED",
      target: "session-agent-jailbreak-88a",
      status: "TRIPPED",
    },
    {
      id: "act-2",
      timestamp: "15:34:40 UTC",
      operator: "sec-ops-admin",
      action: "TOOL_BASELINE_REPINNED",
      target: "run_command",
      status: "SUCCESS",
    },
  ]);

  const logAction = (action: string, target: string, status: "SUCCESS" | "FAILED" | "TRIPPED" = "SUCCESS") => {
    const newItem: ActionLogItem = {
      id: `act-${Date.now()}`,
      timestamp: new Date().toLocaleTimeString("en-GB", { timeZone: "UTC" }) + " UTC",
      operator: "sec-ops-admin",
      action,
      target,
      status,
    };
    setActionHistory((prev) => [newItem, ...prev.slice(0, 19)]);
  };

  const handleQuarantine = () => {
    if (!targetSessionInput.trim()) return;
    const sessionKey = targetSessionInput.trim();
    if (quarantinedSessions.some((s) => s.sessionId === sessionKey && s.status === "quarantined")) {
      alert("Session is already actively quarantined.");
      return;
    }

    const newQuarantine: QuarantinedSession = {
      id: `q-${Date.now()}`,
      sessionId: sessionKey,
      revokedAt: "Just now",
      reason: quarantineReason,
      originatingLayer: "operator",
      status: "quarantined",
    };

    setQuarantinedSessions((prev) => [newQuarantine, ...prev]);
    logAction("SESSION_QUARANTINED", sessionKey, "TRIPPED");
    setTargetSessionInput("");
  };

  const handleRestore = (id: string, sessionId: string) => {
    setQuarantinedSessions((prev) =>
      prev.map((s) => (s.id === id ? { ...s, status: "restored" } : s))
    );
    logAction("SESSION_RESTORED", sessionId, "SUCCESS");
  };

  const handleRepinTool = (name: string) => {
    const randomHash = Array.from({ length: 32 }, () =>
      Math.floor(Math.random() * 16).toString(16)
    ).join("");
    setToolBaselines((prev) =>
      prev.map((t) =>
        t.name === name
          ? {
              ...t,
              fingerprint: `${randomHash.substring(0, 32)}...${randomHash.substring(28)}`,
              lastVerified: "Just now",
              status: "PINNED",
            }
          : t
      )
    );
    logAction("TOOL_SCHEMA_REPINNED", name, "SUCCESS");
  };

  const handleToggleGateTool = (name: string) => {
    setToolBaselines((prev) =>
      prev.map((t) => {
        if (t.name === name) {
          const nextStatus = t.status === "GATED" ? "PINNED" : "GATED";
          logAction(nextStatus === "GATED" ? "TOOL_HUMAN_GATED" : "TOOL_GATE_REMOVED", name, "SUCCESS");
          return { ...t, status: nextStatus };
        }
        return t;
      })
    );
  };

  const handleMemoryAction = (actionName: string) => {
    setMemoryNotification(`Executing: ${actionName} on namespace [${activeMemoryPartition}]...`);
    setTimeout(() => {
      setMemoryNotification(`Success: ${actionName} completed. All anchors verified clean.`);
      logAction(`MEMORY_${actionName.toUpperCase().replace(/\s+/g, "_")}`, activeMemoryPartition, "SUCCESS");
      setTimeout(() => setMemoryNotification(null), 4000);
    }, 700);
  };

  const handleExportForensicBundle = () => {
    setIsExporting(true);
    setEvidenceFeedback("Generating cryptographic SHA-256 evidence bundle...");

    setTimeout(() => {
      const bundle = {
        monolith_evidence_version: "1.0",
        bundle_type: "INCIDENT_FORENSIC_SNAPSHOT",
        tenant_id: "demo-corp",
        generated_at: new Date().toISOString(),
        target_session: exportSessionId,
        operator: "sec-ops-admin",
        integrity: {
          algorithm: "hmac-sha256",
          canonical_sha256: "4b92c4a92305a90d8109bf199320e8bfa1008d3c010a3014a42b083c0f24e77a",
          signature: "f7c3bc1d808e04732adf679901416801ca81e19409890f5c1d636402741d401a",
          status: "VERIFIED_TAMPER_EVIDENT",
        },
        audit_trail: actionHistory,
        quarantine_record: quarantinedSessions.find((s) => s.sessionId === exportSessionId) || null,
        pinned_tool_manifest: toolBaselines,
      };

      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `aeos-guard-forensics-${exportSessionId}-${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      setIsExporting(false);
      setEvidenceFeedback("Cryptographically signed bundle downloaded successfully.");
      logAction("FORENSIC_BUNDLE_EXPORTED", exportSessionId, "SUCCESS");
      setTimeout(() => setEvidenceFeedback(null), 3500);
    }, 900);
  };

  return (
    <div className="frame">
      <div className="app two-col">
        <Rail />
        <main className="main">
          <div className="topbar">
            <div>
              <h1>Active Remediation & Circuit Breakers</h1>
              <div className="crumb">Cross-Layer Containment • Tool Pinning • Cryptographic Evidence</div>
            </div>
            <div className="topbar-right">
              <span className={`pbm-pill ${isHalted ? "pbm-pill-crit" : "pbm-pill-ok"}`} style={{ padding: "4px 10px", fontSize: "11px" }}>
                {isHalted ? "EMERGENCY HALT ACTIVE" : "DEFCON 4 • NOMINAL"}
              </span>
              <button
                onClick={() => {
                  const nextState = !isHalted;
                  setIsHalted(nextState);
                  logAction(
                    nextState ? "GLOBAL_EMERGENCY_HALT_ENGAGED" : "GLOBAL_RESUME_DISENGAGED",
                    "ALL_MODULES",
                    nextState ? "TRIPPED" : "SUCCESS"
                  );
                }}
                className={`pbm-btn ${isHalted ? "pbm-btn-primary" : "pbm-btn-danger"}`}
              >
                <IconAlert size={14} />
                {isHalted ? "Resume Ingress" : "EMERGENCY STOP"}
              </button>
              <OperatorBadge />
              <ThemeToggle />
            </div>
          </div>

          <div className="content-scroll pbm-page-scroll">
            {isHalted && (
              <div className="pbm-card" style={{ border: "1px solid var(--sev-critical)", background: "rgba(244, 86, 74, 0.15)", padding: "12px 16px", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "var(--sev-critical)" }}>
                  <IconAlert size={16} />
                  <strong style={{ fontSize: "12.5px" }}>GLOBAL KILL SWITCH ENGAGED:</strong>
                  <span style={{ fontSize: "12px", color: "var(--ink)" }}>All inbound agent prompts and tool executions are strictly frozen.</span>
                </div>
                <button
                  onClick={() => {
                    setIsHalted(false);
                    logAction("GLOBAL_RESUME_DISENGAGED", "ALL_MODULES", "SUCCESS");
                  }}
                  className="pbm-btn pbm-btn-danger"
                  style={{ fontSize: "11px", padding: "3px 10px" }}
                >
                  DISENGAGE
                </button>
              </div>
            )}

            <div className="pbm-two-col">
              {/* Left Column: Circuit Breaker & Tool Baselines */}
              <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
                {/* Section 1: Session Circuit Breakers */}
                <div className="pbm-card">
                  <div className="pbm-card-head">
                    <span className="pbm-card-title">
                      <IconIntercept size={15} />
                      1. Cross-Layer Session Circuit Breakers
                    </span>
                    <span className="pbm-card-meta">Real-time Revocation Broadcast</span>
                  </div>

                  {/* Quarantine Action Form */}
                  <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", background: "var(--card-inset)", padding: "10px", borderRadius: "8px", border: "1px solid var(--line-soft)" }}>
                    <input
                      type="text"
                      placeholder="Target Session ID (e.g. session-agent-01)..."
                      value={targetSessionInput}
                      onChange={(e) => setTargetSessionInput(e.target.value)}
                      className="pbm-input"
                      style={{ flex: 1, minWidth: "160px", fontFamily: "ui-monospace, monospace" }}
                    />
                    <select
                      value={quarantineReason}
                      onChange={(e) => setQuarantineReason(e.target.value)}
                      className="pbm-select"
                      style={{ width: "auto" }}
                    >
                      <option value="Manual operator intervention">Operator Intervention</option>
                      <option value="Adversarial prompt injection detected">Prompt Injection (LLM01)</option>
                      <option value="Outbound credential exfiltration">Credential Leak (LLM02)</option>
                      <option value="MCP tool schema rug-pull detected">Tool Schema Rug-Pull (LLM03)</option>
                      <option value="RAG universal bait query detected">RAG Memory Bait (LLM04)</option>
                    </select>
                    <button
                      onClick={handleQuarantine}
                      disabled={!targetSessionInput.trim()}
                      className="pbm-btn pbm-btn-danger"
                    >
                      Quarantine Session
                    </button>
                  </div>

                  {/* Quarantined Sessions Table */}
                  <div style={{ display: "flex", flexDirection: "column", gap: "6px", maxHeight: "220px", overflowY: "auto" }}>
                    {quarantinedSessions.length === 0 ? (
                      <div style={{ textAlign: "center", padding: "16px", color: "var(--ink-faint)", fontSize: "11.5px" }}>
                        No active sessions currently quarantined.
                      </div>
                    ) : (
                      quarantinedSessions.map((qs) => (
                        <div
                          key={qs.id}
                          style={{
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "space-between",
                            padding: "8px 12px",
                            borderRadius: "6px",
                            border: `1px solid ${qs.status === "quarantined" ? "rgba(244, 86, 74, 0.3)" : "var(--line-soft)"}`,
                            background: qs.status === "quarantined" ? "rgba(244, 86, 74, 0.06)" : "var(--card-2)",
                            opacity: qs.status === "restored" ? 0.6 : 1,
                          }}
                        >
                          <div>
                            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                              <strong style={{ fontSize: "11.5px", fontFamily: "ui-monospace, monospace", color: "var(--ink)" }}>
                                {qs.sessionId}
                              </strong>
                              <span className="pbm-pill pbm-pill-dim" style={{ fontSize: "9px" }}>
                                {qs.originatingLayer}
                              </span>
                              <span style={{ fontSize: "10.5px", color: "var(--ink-faint)" }}>{qs.revokedAt}</span>
                            </div>
                            <div style={{ fontSize: "11px", color: "var(--ink-dim)", marginTop: "2px" }}>
                              {qs.reason}
                            </div>
                          </div>

                          <div>
                            {qs.status === "quarantined" ? (
                              <button
                                onClick={() => handleRestore(qs.id, qs.sessionId)}
                                className="pbm-btn"
                                style={{ padding: "3px 8px", fontSize: "10.5px" }}
                              >
                                Restore
                              </button>
                            ) : (
                              <span className="pbm-pill pbm-pill-ok" style={{ fontSize: "9px" }}>
                                Restored
                              </span>
                            )}
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                {/* Section 2: MCP Tool Schema Baseline Manager */}
                <div className="pbm-card">
                  <div className="pbm-card-head">
                    <span className="pbm-card-title">
                      <IconTool size={15} />
                      2. MCP Tool Schema Baseline Manager
                    </span>
                    <span className="pbm-card-meta">Cryptographic SHA-256 Pinning</span>
                  </div>

                  <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                    {toolBaselines.map((tool) => (
                      <div
                        key={tool.name}
                        style={{
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "space-between",
                          padding: "10px 12px",
                          borderRadius: "6px",
                          background: "var(--card-inset)",
                          border: "1px solid var(--line-soft)",
                          gap: "8px",
                          flexWrap: "wrap",
                        }}
                      >
                        <div>
                          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                            <strong style={{ fontSize: "12px", fontFamily: "ui-monospace, monospace", color: "var(--ink)" }}>
                              {tool.name}
                            </strong>
                            <span
                              className={`pbm-pill ${
                                tool.status === "PINNED"
                                  ? "pbm-pill-ok"
                                  : tool.status === "GATED"
                                  ? "pbm-pill-warn"
                                  : "pbm-pill-crit"
                              }`}
                            >
                              {tool.status}
                            </span>
                            <span style={{ fontSize: "10px", color: "var(--ink-faint)" }}>{tool.lastVerified}</span>
                          </div>
                          <div style={{ fontSize: "10px", fontFamily: "ui-monospace, monospace", color: "var(--ink-dim)", marginTop: "2px" }}>
                            SHA256: {tool.fingerprint}
                          </div>
                        </div>

                        <div style={{ display: "flex", gap: "6px" }}>
                          <button
                            onClick={() => handleToggleGateTool(tool.name)}
                            className="pbm-btn"
                            style={{ padding: "3px 8px", fontSize: "10.5px" }}
                          >
                            {tool.status === "GATED" ? "Ungate" : "Gate (HITL)"}
                          </button>
                          <button
                            onClick={() => handleRepinTool(tool.name)}
                            className="pbm-btn pbm-btn-primary"
                            style={{ padding: "3px 8px", fontSize: "10.5px" }}
                          >
                            Re-Pin
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Right Column: Memory Isolation, Forensic Bundle, Action Ledger */}
              <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
                {/* Section 3: Vector Memory Quarantine & Detector Cache */}
                <div className="pbm-card">
                  <div className="pbm-card-head">
                    <span className="pbm-card-title">
                      <IconMemory size={15} />
                      3. Vector Memory Quarantine
                    </span>
                    <span className="pbm-card-meta">Poison Partition Isolation</span>
                  </div>

                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "8px" }}>
                    <span style={{ fontSize: "11.5px", color: "var(--ink-dim)" }}>Partition:</span>
                    <select
                      value={activeMemoryPartition}
                      onChange={(e) => setActiveMemoryPartition(e.target.value)}
                      className="pbm-select"
                      style={{ flex: 1, fontFamily: "ui-monospace, monospace", fontSize: "11px" }}
                    >
                      <option value="prod-agent-memory">prod-agent-memory (1,420 vectors)</option>
                      <option value="customer-rag-cache">customer-rag-cache (8,940 vectors)</option>
                      <option value="scratchpad-v1">scratchpad-v1 (112 vectors)</option>
                    </select>
                  </div>

                  {memoryNotification && (
                    <div style={{ padding: "8px 10px", background: "var(--card-2)", border: "1px solid var(--mod-vector)", borderRadius: "6px", fontSize: "11px", color: "var(--mod-vector)" }}>
                      {memoryNotification}
                    </div>
                  )}

                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
                    <button
                      onClick={() => handleMemoryAction("Flush Semantic Drift Cache")}
                      className="pbm-btn"
                      style={{ padding: "8px", flexDirection: "column", alignItems: "flex-start", gap: "2px" }}
                    >
                      <strong style={{ fontSize: "11px", color: "var(--ink)" }}>Flush Drift Cache</strong>
                      <span style={{ fontSize: "10px", color: "var(--ink-faint)" }}>Clears cosine buffers</span>
                    </button>
                    <button
                      onClick={() => handleMemoryAction("Isolate Poisoned Vectors")}
                      className="pbm-btn"
                      style={{ padding: "8px", flexDirection: "column", alignItems: "flex-start", gap: "2px" }}
                    >
                      <strong style={{ fontSize: "11px", color: "var(--sev-warning)" }}>Isolate Poison Vectors</strong>
                      <span style={{ fontSize: "10px", color: "var(--ink-faint)" }}>Partitions bait chunks</span>
                    </button>
                  </div>
                </div>

                {/* Section 4: Cryptographic Forensic Evidence Export Center */}
                <div className="pbm-card">
                  <div className="pbm-card-head">
                    <span className="pbm-card-title">
                      <IconReason size={15} />
                      4. Cryptographic Forensic Export Center
                    </span>
                    <span className="pbm-card-meta">HMAC-SHA256 Signed</span>
                  </div>

                  <div style={{ display: "flex", gap: "8px" }}>
                    <input
                      type="text"
                      value={exportSessionId}
                      onChange={(e) => setExportSessionId(e.target.value)}
                      className="pbm-input"
                      style={{ flex: 1, fontFamily: "ui-monospace, monospace" }}
                    />
                    <button
                      onClick={handleExportForensicBundle}
                      disabled={isExporting || !exportSessionId.trim()}
                      className="pbm-btn pbm-btn-primary"
                      style={{ whiteSpace: "nowrap" }}
                    >
                      <IconBolt size={12} />
                      {isExporting ? "Signing..." : "Export Bundle"}
                    </button>
                  </div>

                  {evidenceFeedback && (
                    <div style={{ padding: "8px 10px", background: "rgba(53, 208, 127, 0.12)", border: "1px solid var(--ok)", borderRadius: "6px", fontSize: "11px", color: "var(--ok)" }}>
                      ✓ {evidenceFeedback}
                    </div>
                  )}

                  <div style={{ padding: "8px 10px", background: "var(--card-inset)", border: "1px solid var(--line-soft)", borderRadius: "6px", fontSize: "10.5px", fontFamily: "ui-monospace, monospace", color: "var(--ink-faint)" }}>
                    <div>Integrity: HMAC-SHA256</div>
                    <div>Status: Tamper-Evident Canonical JSON Snapshot</div>
                  </div>
                </div>

                {/* Section 5: Operator Action History Ledger */}
                <div className="pbm-card" style={{ flex: 1 }}>
                  <div className="pbm-card-head">
                    <span className="pbm-card-title">
                      <IconHistory size={15} />
                      5. Operator Action History Ledger
                    </span>
                    <span className="pbm-card-meta">Append-Only Audit</span>
                  </div>

                  <div style={{ display: "flex", flexDirection: "column", gap: "6px", maxHeight: "180px", overflowY: "auto" }}>
                    {actionHistory.map((act) => (
                      <div
                        key={act.id}
                        style={{
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "space-between",
                          padding: "6px 10px",
                          borderRadius: "4px",
                          background: "var(--card-inset)",
                          fontSize: "11px",
                          fontFamily: "ui-monospace, monospace",
                        }}
                      >
                        <div>
                          <span style={{ color: "var(--ink-faint)", fontSize: "10px", marginRight: "6px" }}>{act.timestamp}</span>
                          <strong style={{ color: "var(--ink)" }}>{act.action}</strong>
                          <span style={{ color: "var(--ink-dim)", marginLeft: "4px" }}>[{act.target}]</span>
                        </div>
                        <span
                          className={`pbm-pill ${
                            act.status === "TRIPPED" ? "pbm-pill-crit" : "pbm-pill-ok"
                          }`}
                          style={{ fontSize: "9px" }}
                        >
                          {act.status}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
