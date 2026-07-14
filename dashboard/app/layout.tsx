import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Project Black Monolith — Threat Dashboard",
  description:
    "Unified real-time threat feed for the Project Black Monolith agent-security modules.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
