"use client";

import { useCallback, useEffect, useState } from "react";

const KEY = "monolith-operator-token";

/**
 * The operator's credential for the investigation queue.
 *
 * This replaces the self-declared analyst name that used to live here. The name
 * recorded in the audit trail is now derived server-side from this token, so a
 * caller can no longer write someone else's name against a decision — an actor
 * you can name yourself is not evidence.
 *
 * The token is held in localStorage, which is honest about what this is: a
 * single-operator local console, not a session-managed application. It is a
 * bearer credential, so anything with access to this browser profile has it.
 */
export function useOperatorToken(): [string, (token: string) => void, boolean] {
  const [token, setToken] = useState("");
  // Server and first client render must agree, so the stored token is only
  // adopted after mount. `ready` lets callers avoid flashing a signed-out state.
  const [ready, setReady] = useState(false);

  useEffect(() => {
    try {
      setToken(localStorage.getItem(KEY) ?? "");
    } catch {
      /* storage unavailable (private mode) — the operator can still paste one */
    }
    setReady(true);
  }, []);

  const update = useCallback((next: string) => {
    const trimmed = next.trim();
    setToken(trimmed);
    try {
      if (trimmed) localStorage.setItem(KEY, trimmed);
      else localStorage.removeItem(KEY);
    } catch {
      /* non-fatal: it just will not persist across reloads */
    }
  }, []);

  return [token, update, ready];
}
