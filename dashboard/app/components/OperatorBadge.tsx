"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { IconUser } from "./Icons";

type Identity = { actor: string; role: string; tenant_id: string };

export default function OperatorBadge() {
  const router = useRouter();
  const [identity, setIdentity] = useState<Identity | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/auth/session")
      .then(async (response) => {
        if (response.status === 401) {
          router.replace("/login");
          router.refresh();
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
    if (response.ok) {
      setIdentity(null);
      router.replace("/login");
      router.refresh();
    }
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
