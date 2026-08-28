"use client";

// The operator identity badge in every page's top bar.
//
// WHAT THIS FILE IS
// -----------------
// Fetches the current identity (GET /api/auth/session) and renders the actor
// name + role. Clicking the badge signs out (DELETE /api/auth/session).
//
// THE REDIRECT-ON-401 BEHAVIOR
// ----------------------------
// A 401 from the session endpoint means "not signed in" — the browser is
// sent to /login. That is what gates the whole dashboard: every page mounts
// this badge, so an unauthenticated visitor is bounced to the login page.
//
// Note: the /api/auth/session GET route has its own handling of the demo
// escape hatch (MONOLITH_DISABLE_AUTH), so this badge never causes a reload
// loop in that mode.

import { useEffect, useState } from "react";
import { IconUser } from "./Icons";

type Identity = { actor: string; role: string; tenant_id: string };

export default function OperatorBadge() {
  const [identity, setIdentity] = useState<Identity | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/auth/session")
      .then(async (response) => {
        if (response.status === 401) {
          window.location.assign("/login");
          return null;
        }
        return response.ok ? response.json() : null;
      })
      .then((value) => {
        if (!cancelled && value?.authenticated) setIdentity(value);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  async function logout() {
    const response = await fetch("/api/auth/session", { method: "DELETE" });
    if (response.ok) window.location.assign("/login");
  }

  return (
    <button
      className="operator-badge"
      onClick={logout}
      title={identity ? `Tenant ${identity.tenant_id} · click to sign out` : "Operator session"}
    >
      <IconUser size={13} />
      <span>{identity?.actor ?? "operator"}</span>
      {identity ? <span className="operator-role">{identity.role}</span> : null}
    </button>
  );
}
