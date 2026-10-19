import { NextRequest, NextResponse } from "next/server";

const OPERATOR_SESSION_COOKIE = "monolith-session";

export function isAuthDisabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const key = "MONOLITH_DISABLE_AUTH";
  // Exact match only, matching lib/route-auth.ts. A looser comparison would
  // let a value that means nothing on the secure path disable the page guard
  // and the operator checks behind it.
  return env[key] === "true";
}

/**
 * Page guard only. API routes validate the opaque session against Postgres;
 * the proxy checks presence so unauthenticated browsers reach the login page
 * instead of rendering a console that can only receive 401 responses.
 */
export function proxy(req: NextRequest) {
  // Read at runtime on each request so MONOLITH_DISABLE_AUTH is never baked
  // into the Docker image at build time.
  const authDisabled = isAuthDisabled();
  const onLogin = req.nextUrl.pathname === "/login";

  if (authDisabled) {
    // Send /login to the console too. Without this a cached redirect or a
    // bookmark still lands on a sign-in form that can no longer sign anyone in.
    return onLogin ? NextResponse.redirect(new URL("/", req.url)) : NextResponse.next();
  }
  if (onLogin || req.cookies.has(OPERATOR_SESSION_COOKIE)) return NextResponse.next();
  const login = new URL("/login", req.url);
  login.searchParams.set("next", `${req.nextUrl.pathname}${req.nextUrl.search}`);
  return NextResponse.redirect(login);
}

export const config = {
  matcher: ["/", "/login", "/investigate/:path*", "/benchmarks/:path*", "/operations/:path*"],
};
