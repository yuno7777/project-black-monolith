"use client";

import { useCallback, useEffect, useState } from "react";

const KEY = "monolith-analyst";
const FALLBACK = "unassigned-operator";

/**
 * The identity recorded against triage actions.
 *
 * This is an *attribution label*, not authentication: the dashboard has no user
 * model, and this value is self-declared and stored in localStorage. It exists
 * so the audit trail reads as something other than a wall of "unknown" on a
 * single-operator stack. Anything multi-user needs a real identity layer in
 * front of /api/incidents — see the dashboard README.
 */
export function useAnalyst(): [string, (name: string) => void] {
  // Start on the fallback so the server and first client render agree; the
  // stored name is adopted after mount.
  const [analyst, setAnalyst] = useState(FALLBACK);

  useEffect(() => {
    try {
      const stored = localStorage.getItem(KEY);
      if (stored) setAnalyst(stored);
    } catch {
      /* storage unavailable (private mode) — keep the fallback */
    }
  }, []);

  const update = useCallback((name: string) => {
    const trimmed = name.trim().slice(0, 128) || FALLBACK;
    setAnalyst(trimmed);
    try {
      localStorage.setItem(KEY, trimmed);
    } catch {
      /* non-fatal: the name just will not persist across reloads */
    }
  }, []);

  return [analyst, update];
}
