import { NextRequest, NextResponse } from "next/server";

const OPERATOR_SESSION_COOKIE = "monolith-session";

/**
 * Page guard only. API routes validate the opaque session against Postgres;
 * the proxy checks presence so unauthenticated browsers reach the login page
 * instead of rendering a console that can only receive 401 responses.
 */
export function proxy(req: NextRequest) {
  if (req.cookies.has(OPERATOR_SESSION_COOKIE)) return NextResponse.next();
  const login = new URL("/login", req.url);
  login.searchParams.set("next", `${req.nextUrl.pathname}${req.nextUrl.search}`);
  return NextResponse.redirect(login);
}

export const config = {
  matcher: ["/", "/investigate/:path*", "/benchmarks/:path*", "/operations/:path*"],
};
