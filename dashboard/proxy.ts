import { NextRequest, NextResponse } from "next/server";

const OPERATOR_SESSION_COOKIE = "monolith-session";

/**
 * Page guard only. API routes validate the opaque session against Postgres;
 * the proxy checks presence so unauthenticated browsers reach the login page
 * instead of rendering a console that can only receive 401 responses.
 */
export function proxy(req: NextRequest) {
  // Matches the API-side escape hatch in lib/route-auth.ts. Read at module
  // scope because middleware env is resolved when the bundle is built, so
  // toggling this takes a rebuild (`docker compose up -d --build`).
  const authDisabled = process.env.MONOLITH_DISABLE_AUTH === "true";
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
