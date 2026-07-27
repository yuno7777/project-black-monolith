"use client";

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
