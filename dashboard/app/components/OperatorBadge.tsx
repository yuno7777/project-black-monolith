"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { IconUser } from "./Icons";

type Identity = { actor: string; role: string; tenant_id: string };

export default function OperatorBadge() {
  const [identity, setIdentity] = useState<Identity | null>(null);
  const router = useRouter();

  useEffect(() => {
    let cancelled = false;
    fetch("/api/auth/session")
      .then(async (response) => {
        if (response.status === 401) {
          // A client-side navigation, not a full page load: the live feed
          // behind this badge holds an open event stream, and reloading the
          // whole document would tear it down and re-run the initial fetch
          // for data the operator is about to be redirected away from.
          if (!cancelled) router.push("/login");
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
  }, [router]);

  async function logout() {
    const response = await fetch("/api/auth/session", { method: "DELETE" });
    if (response.ok) router.push("/login");
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
