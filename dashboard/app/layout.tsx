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
