// The root layout for every page of the dashboard.
//
// WHAT THIS FILE IS
// -----------------
// The Next.js App Router root layout. It wraps all pages in the shared <html>
// shell and — the important part — stamps the theme BEFORE first paint.
//
// WHY THE INLINE THEME SCRIPT
// ---------------------------
// The dashboard is a dark-first security console (black canvas, glass cards).
// If the theme were applied by React after hydration, a light-mode user would
// see a dark flash (or vice versa) on every load. The inline script runs
// before first paint and sets data-theme on <html> from localStorage
// ("monolith-theme" === "light" ? light : dark), so the page is painted
// correctly the first time. Dark is the product default regardless of the OS
// setting; light is only ever an explicit choice. The charts read colors from
// CSS variables (var(--ink), var(--mod-*)), so they follow the theme.

import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Project Black Monolith — Threat Dashboard",
  description:
    "Unified real-time threat feed for the Project Black Monolith agent-security modules.",
};

// Runs before first paint: stamps the theme on <html> so it is painted
// immediately rather than flashing and correcting itself once React hydrates.
// Dark is the product default regardless of the OS setting — this is a
// black-canvas security console — so light is only ever an explicit choice.
const themeScript = `
(function () {
  try {
    document.documentElement.dataset.theme =
      localStorage.getItem("monolith-theme") === "light" ? "light" : "dark";
  } catch (e) {
    document.documentElement.dataset.theme = "dark";
  }
})();
`;

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
