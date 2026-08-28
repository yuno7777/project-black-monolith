// The operator sign-in page (route "/login").
//
// WHAT THIS PAGE IS
// -----------------
// A minimal form that exchanges the long-lived operator bootstrap token for a
// revocable browser session. It is a client component because it submits a
// form and handles the response.
//
// THE FLOW (user signs in)
// ------------------------
//   User types the operator token (from .env MONOLITH_OPERATOR_TOKEN)
//    -> POST /api/auth/session { token }         [app/api/auth/session/route.ts]
//    -> server rate-limits, validates the credential (local token or OIDC),
//       creates the session row (SHA-256 digest), and sets the HttpOnly
//       SameSite=Strict cookie
//    -> on success, window.location.assign(next) — a FULL page navigation so
//       every subsequent server/client request immediately carries the new
//       cookie
//
// WHY THE FULL NAVIGATION INSTEAD OF CLIENT-SIDE STATE
// ----------------------------------------------------
// The session cookie is HttpOnly — JavaScript can't read it. A client-side
// "signed in!" state would be invisible to the server until the next request;
// a full navigation guarantees the very next request is authenticated.
//
// safeNext() guards the ?next= redirect parameter (open-redirect defense):
// only same-origin paths are honored; anything else falls back to "/".

"use client";

import { FormEvent, Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import { Logo } from "../components/Icons";
import ThemeToggle from "../components/ThemeToggle";

function safeNext(value: string | null): string {
  // Open-redirect defense: only allow same-origin paths in ?next=.
  if (!value) return "/";
  try {
    const base = new URL("http://monolith.local");
    const target = new URL(value, base);
    return target.origin === base.origin
      ? `${target.pathname}${target.search}${target.hash}`
      : "/";
  } catch {
    return "/";
  }
}

function LoginForm() {
  const next = safeNext(useSearchParams().get("next"));
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const response = await fetch("/api/auth/session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
      });
      const data = await response.json();
      if (!response.ok) {
        setError(data.error ?? "sign-in was rejected");
        return;
      }
      // A full navigation ensures every server/client request immediately sees
      // the new HttpOnly cookie.
      window.location.assign(next);
    } catch {
      setError("could not reach the authentication service");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-shell">
      <div className="login-theme"><ThemeToggle /></div>
      <form className="card login-card" onSubmit={submit}>
        <span className="login-logo"><Logo size={66} /></span>
        <div>
          <div className="login-kicker">Project Black Monolith</div>
          <h1>Operator sign in</h1>
          <p>
            Exchange your operator credential for an expiring, revocable browser
            session. The bootstrap credential is not persisted in the browser.
          </p>
        </div>
        <label className="login-label" htmlFor="operator-token">Operator token</label>
        <input
          id="operator-token"
          className="login-input"
          type="password"
          value={token}
          onChange={(event) => setToken(event.target.value)}
          autoComplete="current-password"
          spellCheck={false}
          required
          autoFocus
        />
        {error ? <div className="panel-error">{error}</div> : null}
        <button className="act primary login-submit" disabled={busy || !token.trim()}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </main>
  );
}

export default function LoginPage() {
  // Suspense is required because useSearchParams must be inside a boundary
  // during static rendering.
  return (
    <Suspense fallback={null}>
      <LoginForm />
    </Suspense>
  );
}
