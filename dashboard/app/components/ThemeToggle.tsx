"use client";

import { useEffect, useState } from "react";
import { IconSun, IconMoon } from "./Icons";

export type Theme = "light" | "dark";

/** Read whatever the pre-paint script in layout.tsx already resolved, so the
 *  button's first render matches the painted theme instead of fighting it. */
function currentTheme(): Theme {
  if (typeof document === "undefined") return "dark";
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

export default function ThemeToggle() {
  // Mount-gated: the server cannot know the stored choice, so the first render
  // must match the server's markup and the real icon swaps in after hydration.
  const [theme, setTheme] = useState<Theme>("dark");
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setTheme(currentTheme());
    setMounted(true);
  }, []);

  const toggle = () => {
    const next: Theme = theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try {
      localStorage.setItem("monolith-theme", next);
    } catch {
      /* private mode — the theme still applies for this session */
    }
    setTheme(next);
  };

  return (
    <button
      className="iconbtn"
      onClick={toggle}
      aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
      title={theme === "dark" ? "Light theme" : "Dark theme"}
      suppressHydrationWarning
    >
      {mounted && theme === "light" ? <IconMoon /> : <IconSun />}
    </button>
  );
}
