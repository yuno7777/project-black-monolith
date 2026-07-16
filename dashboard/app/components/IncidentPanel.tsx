"use client";

import { useEffect, useState } from "react";
import type { AuditEntry, Incident, IncidentStatus, Resolution, SessionView } from "@/lib/types";
import {
  MODULE_ACCENT,
  MODULE_LABELS,
  MODULE_LAYER,
  RESOLUTIONS,
  RESOLUTION_LABELS,
  STATUS_LABELS,
} from "@/lib/types";
import {
  ModuleGlyph,
  SevIcon,
  IconEye,
  IconCheck,
  IconUser,
  IconHistory,
  IconAlert,
} from "./Icons";

function stamp(ms: number): string {
  if (!Number.isFinite(ms)) return "—";
  return new Date(ms).toLocaleString([], { hour12: false });
}

export interface TransitionRequest {
  status: IncidentStatus;
  assignee?: string;
  /** Assign to whoever the operator token authenticates as. */
  assign_to_me?: boolean;
  note?: string;
  resolution?: Resolution;
}

export default function IncidentPanel({
  incident,
  onTransition,
  onClose,
  onSelectSession,
}: {
  incident: Incident;
  onTransition: (t: TransitionRequest) => Promise<string | null>;
  onClose: () => void;
  /** Show every detection from this agent session in the queue. */
  onSelectSession?: (sessionId: string) => void;
}) {
  const status = incident.triage?.status ?? "new";
  const accent = MODULE_ACCENT[incident.module] ?? "var(--ink-faint)";

  const [note, setNote] = useState("");
  const [resolution, setResolution] = useState<Resolution>("true_positive");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [audit, setAudit] = useState<AuditEntry[] | null>(null);
  const [session, setSession] = useState<SessionView | null>(null);

  // Reset the draft when switching incidents — a note typed for one incident
  // must never be carried into another.
  useEffect(() => {
    setNote("");
    setResolution("true_positive");
    setError(null);
    setAudit(null);
    setSession(null);
  }, [incident.event_id]);

  // What else this agent session did. A 404 means the event carries no session
  // and simply cannot be correlated — not an error worth showing.
  useEffect(() => {
    let cancelled = false;
    fetch(`/api/incidents/${incident.event_id}/session`)
      .then((r) => (r.ok ? r.json() : { session: null }))
      .then((d) => {
        if (!cancelled) setSession(d.session ?? null);
      })
      .catch(() => {
        if (!cancelled) setSession(null);
      });
    return () => {
      cancelled = true;
    };
  }, [incident.event_id]);

  useEffect(() => {
    let cancelled = false;
    fetch(`/api/incidents/${incident.event_id}/audit`)
      .then((r) => (r.ok ? r.json() : { audit: [] }))
      .then((d) => {
        if (!cancelled) setAudit(d.audit ?? []);
      })
      .catch(() => {
        if (!cancelled) setAudit([]);
      });
    return () => {
      cancelled = true;
    };
    // triage?.updated_ms in the deps refetches the trail after each transition.
  }, [incident.event_id, incident.triage?.updated_ms]);

  async function run(t: TransitionRequest) {
    setBusy(true);
    setError(null);
    const message = await onTransition(t);
    setBusy(false);
    if (message) setError(message);
    else setNote("");
  }

  return (
    <div className="card panel-card">
      <div className="card-head">
        <div>
          <span className="card-title">Incident</span>
          <div className="card-meta" style={{ marginTop: 3 }}>
            <span className="mono-id">{incident.event_id}</span>
          </div>
        </div>
        <button className="ghost-btn" onClick={onClose} aria-label="Close incident">
          Close
        </button>
      </div>

      <div className="panel-body">
        <div className="panel-tags">
          <span className="badge" style={{ ["--accent-mod" as string]: accent }}>
            <ModuleGlyph module={incident.module} size={13} />
            {MODULE_LABELS[incident.module] ?? incident.module}
          </span>
          <span className={`sev ${incident.severity}`}>
            <SevIcon severity={incident.severity} />
            {incident.severity}
          </span>
          <span className={`status-pill ${status}`}>{STATUS_LABELS[status]}</span>
        </div>

        <div className="panel-type">{incident.event_type}</div>
        <div className="panel-when">Detected {stamp(incident.timestamp_ms)}</div>

        {incident.triage?.assignee ? (
          <div className="panel-assignee">
            <IconUser size={13} /> Assigned to {incident.triage.assignee}
          </div>
        ) : null}

        {session ? (
          <>
            <div className="panel-label">Agent session</div>
            {session.cross_layer ? (
              // The finding no single module can make: one agent tripped more
              // than one layer of the defense.
              <div className="cross-layer">
                <span className="cl-head">
                  <IconAlert size={14} />
                  {session.layers.length} of 3 layers flagged this session
                </span>
                <span className="cl-sub">
                  A single detection is an incident. The same agent tripping the
                  tool, memory and reasoning layers is a compromised session —
                  escalate rather than triage each in isolation.
                </span>
              </div>
            ) : null}
            <div className="session-layers">
              {session.layers.map((l) => (
                <div
                  className="session-layer"
                  key={l.module}
                  style={{ ["--accent-mod" as string]: MODULE_ACCENT[l.module] ?? "var(--ink-faint)" }}
                >
                  <span className="sl-ic"><ModuleGlyph module={l.module} size={15} /></span>
                  <span className="sl-main">
                    <span className="sl-name">{MODULE_LABELS[l.module] ?? l.module}</span>
                    <span className="sl-layer">{MODULE_LAYER[l.module] ?? "unknown layer"}</span>
                  </span>
                  <span className={`sev ${l.worst}`}>
                    <SevIcon severity={l.worst} />
                    {l.worst}
                  </span>
                  <span className="sl-n num">{l.events}</span>
                </div>
              ))}
            </div>
            <div className="session-foot">
              <span className="mono-id">{session.session_id}</span>
              {onSelectSession ? (
                <button className="ghost-btn" onClick={() => onSelectSession(session.session_id)}>
                  Show all {session.total}
                </button>
              ) : null}
            </div>
          </>
        ) : null}

        <div className="panel-label">Evidence</div>
        <pre className="panel-json">{JSON.stringify(incident.details ?? {}, null, 2)}</pre>

        {incident.triage?.note ? (
          <>
            <div className="panel-label">Latest note</div>
            <div className="panel-note">{incident.triage.note}</div>
          </>
        ) : null}

        <div className="panel-label">Triage</div>
        <textarea
          className="panel-input"
          rows={2}
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder="Add a note (recorded in the audit trail)…"
          maxLength={2000}
        />

        {error ? <div className="panel-error">{error}</div> : null}

        <div className="panel-actions">
          <button
            className="act"
            disabled={busy || status === "acknowledged"}
            onClick={() => run({ status: "acknowledged", assign_to_me: true, note: note || undefined })}
          >
            <IconEye size={14} />
            {status === "acknowledged" ? "Acknowledged" : "Acknowledge & take"}
          </button>

          <span className="act-group">
            <select
              className="panel-select"
              value={resolution}
              onChange={(e) => setResolution(e.target.value as Resolution)}
              aria-label="Resolution"
              disabled={busy}
            >
              {RESOLUTIONS.map((r) => (
                <option key={r} value={r}>
                  {RESOLUTION_LABELS[r]}
                </option>
              ))}
            </select>
            <button
              className="act primary"
              disabled={busy}
              onClick={() =>
                // No assignee: omitting it leaves the existing owner alone, and
                // resolving someone else's case must not silently reassign it.
                run({ status: "resolved", resolution, note: note || undefined })
              }
            >
              <IconCheck size={14} />
              Resolve
            </button>
          </span>

          {status === "resolved" ? (
            <button
              className="act"
              disabled={busy}
              onClick={() => run({ status: "new", note: note || undefined })}
            >
              Reopen
            </button>
          ) : null}
        </div>

        <div className="panel-label">
          <IconHistory size={13} /> Audit trail
        </div>
        {audit === null ? (
          <div className="panel-muted">Loading…</div>
        ) : audit.length === 0 ? (
          <div className="panel-muted">Not triaged yet — no transitions recorded.</div>
        ) : (
          <ol className="trail">
            {audit.map((a) => (
              <li key={a.audit_id}>
                <span className="trail-dot" />
                <div>
                  <div className="trail-head">
                    <strong>{a.actor}</strong>
                    {a.from_status ? ` moved ${STATUS_LABELS[a.from_status]} → ` : " set "}
                    <span className={`status-pill ${a.to_status}`}>{STATUS_LABELS[a.to_status]}</span>
                    {a.resolution ? ` · ${RESOLUTION_LABELS[a.resolution]}` : ""}
                  </div>
                  <div className="trail-when">{stamp(a.at_ms)}</div>
                  {a.note ? <div className="trail-note">{a.note}</div> : null}
                </div>
              </li>
            ))}
          </ol>
        )}
      </div>
    </div>
  );
}
