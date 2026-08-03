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
  if (process.env.MONOLITH_DISABLE_AUTH === "true") return NextResponse.next();
  if (req.cookies.has(OPERATOR_SESSION_COOKIE)) return NextResponse.next();
  const login = new URL("/login", req.url);
  login.searchParams.set("next", `${req.nextUrl.pathname}${req.nextUrl.search}`);
  return NextResponse.redirect(login);
}

export const config = {
  matcher: ["/", "/investigate/:path*", "/benchmarks/:path*", "/operations/:path*"],
};
