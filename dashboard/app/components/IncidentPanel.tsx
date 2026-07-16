"use client";

import { useEffect, useState } from "react";
import type { AuditEntry, Incident, IncidentStatus, Resolution } from "@/lib/types";
import {
  MODULE_ACCENT,
  MODULE_LABELS,
  RESOLUTIONS,
  RESOLUTION_LABELS,
  STATUS_LABELS,
} from "@/lib/types";
import { ModuleGlyph, SevIcon, IconEye, IconCheck, IconUser, IconHistory } from "./Icons";

function stamp(ms: number): string {
  if (!Number.isFinite(ms)) return "—";
  return new Date(ms).toLocaleString([], { hour12: false });
}

export interface TransitionRequest {
  status: IncidentStatus;
  assignee?: string;
  note?: string;
  resolution?: Resolution;
}

export default function IncidentPanel({
  incident,
  analyst,
  onTransition,
  onClose,
}: {
  incident: Incident;
  analyst: string;
  onTransition: (t: TransitionRequest) => Promise<string | null>;
  onClose: () => void;
}) {
  const status = incident.triage?.status ?? "new";
  const accent = MODULE_ACCENT[incident.module] ?? "var(--ink-faint)";

  const [note, setNote] = useState("");
  const [resolution, setResolution] = useState<Resolution>("true_positive");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [audit, setAudit] = useState<AuditEntry[] | null>(null);

  // Reset the draft when switching incidents — a note typed for one incident
  // must never be carried into another.
  useEffect(() => {
    setNote("");
    setResolution("true_positive");
    setError(null);
    setAudit(null);
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
            onClick={() => run({ status: "acknowledged", assignee: analyst, note: note || undefined })}
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
                run({
                  status: "resolved",
                  resolution,
                  assignee: incident.triage?.assignee ?? analyst,
                  note: note || undefined,
                })
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
