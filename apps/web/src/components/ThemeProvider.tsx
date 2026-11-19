"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { flushSync } from "react-dom";
import { Monitor, Moon, Sun } from "lucide-react";
import { cn } from "@/lib/cn";

export type ThemePreference = "dark" | "light" | "system";
export type ResolvedTheme = "dark" | "light";

const STORAGE_KEY = "vforge-theme";
const COOKIE_KEY = "vforge_theme";

interface ThemeContextValue {
  theme: ThemePreference;
  resolvedTheme: ResolvedTheme;
  setTheme: (next: ThemePreference) => void;
  toggleTheme: () => void;
}

const ThemeContext = createContext<ThemeContextValue>({
  theme: "dark",
  resolvedTheme: "dark",
  setTheme: () => {},
  toggleTheme: () => {},
});

export function useTheme() {
  return useContext(ThemeContext);
}

function getSystemTheme(): ResolvedTheme {
  if (typeof window === "undefined" || !window.matchMedia) {
    return "dark";
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

function resolvePreference(pref: ThemePreference): ResolvedTheme {
  if (pref === "system") {
    return getSystemTheme();
  }
  return pref;
}

function applyThemeToDom(pref: ThemePreference, resolved: ResolvedTheme) {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  root.dataset.theme = resolved;
  root.dataset.themePreference = pref;
  root.classList.toggle("dark", resolved === "dark");
  root.classList.toggle("light", resolved === "light");
  root.style.colorScheme = resolved;
}

function persistThemePreference(pref: ThemePreference) {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(STORAGE_KEY, pref);
  } catch {
    // localStorage may be unavailable in restricted contexts
  }
  try {
    document.cookie = `${COOKIE_KEY}=${pref}; Path=/; Max-Age=31536000; SameSite=Lax`;
  } catch {
    // ignore cookie write errors
  }
}

type DocumentWithViewTransition = Document & {
  startViewTransition?: (callback: () => void) => {
    finished: Promise<void>;
  };
};

function runSmoothThemeUpdate(
  nextPref: ThemePreference,
  commitReactState: () => void,
) {
  const nextResolved = resolvePreference(nextPref);
  persistThemePreference(nextPref);

  if (typeof document === "undefined") {
    commitReactState();
    return;
  }

  const root = document.documentElement;
  const currentResolved =
    root.dataset.theme === "light" ? "light" : "dark";
  const docWithVT = document as DocumentWithViewTransition;
  const reducedMotion =
    typeof window !== "undefined" &&
    window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

  // Use native View Transitions API when resolved theme visually changes
  if (
    typeof docWithVT.startViewTransition === "function" &&
    !reducedMotion &&
    currentResolved !== nextResolved
  ) {
    docWithVT.startViewTransition(() => {
      flushSync(() => {
        commitReactState();
      });
      applyThemeToDom(nextPref, nextResolved);
    });
    return;
  }

  // Fallback or preference-only switch (e.g. Dark -> System when OS is Dark):
  // suppress per-element transition tearing cleanly across a single paint frame
  root.classList.add("theme-switching");
  flushSync(() => {
    commitReactState();
  });
  applyThemeToDom(nextPref, nextResolved);
  requestAnimationFrame(() => {
    root.classList.remove("theme-switching");
  });
}

export function ThemeProvider({
  initialPreference = "dark",
  children,
}: {
  initialPreference?: ThemePreference;
  children: ReactNode;
}) {
  const [theme, setThemeState] = useState<ThemePreference>(() => {
    if (typeof window !== "undefined") {
      try {
        const stored = window.localStorage.getItem(STORAGE_KEY);
        if (stored === "dark" || stored === "light" || stored === "system") {
          return stored;
        }
      } catch {
        // ignore storage access issues
      }
    }
    return initialPreference;
  });

  const [systemTheme, setSystemTheme] = useState<ResolvedTheme>(() =>
    getSystemTheme(),
  );

  const resolvedTheme: ResolvedTheme =
    theme === "system" ? systemTheme : theme;

  useEffect(() => {
    applyThemeToDom(theme, resolvedTheme);
  }, [theme, resolvedTheme]);

  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return;
    const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
    const handleMediaChange = (e: MediaQueryListEvent) => {
      const nextSys: ResolvedTheme = e.matches ? "dark" : "light";
      setSystemTheme(nextSys);
    };

    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === STORAGE_KEY) {
        const val = e.newValue;
        if (val === "dark" || val === "light" || val === "system") {
          setThemeState(val);
        }
      }
    };

    mediaQuery.addEventListener("change", handleMediaChange);
    window.addEventListener("storage", handleStorageChange);
    return () => {
      mediaQuery.removeEventListener("change", handleMediaChange);
      window.removeEventListener("storage", handleStorageChange);
    };
  }, []);

  const setTheme = useCallback((next: ThemePreference) => {
    runSmoothThemeUpdate(next, () => {
      setThemeState(next);
    });
  }, []);

  const toggleTheme = useCallback(() => {
    const nextPref: ThemePreference =
      resolvePreference(theme) === "dark" ? "light" : "dark";
    runSmoothThemeUpdate(nextPref, () => {
      setThemeState(nextPref);
    });
  }, [theme]);

  const value = useMemo<ThemeContextValue>(
    () => ({
      theme,
      resolvedTheme,
      setTheme,
      toggleTheme,
    }),
    [theme, resolvedTheme, setTheme, toggleTheme],
  );

  return (
    <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
  );
}

export function ThemeToggle({
  variant = "icon",
  fullWidth = false,
  className,
}: {
  variant?: "icon" | "segmented";
  fullWidth?: boolean;
  className?: string;
}) {
  const { theme, resolvedTheme, setTheme, toggleTheme } = useTheme();

  if (variant === "segmented") {
    const items: Array<{
      id: ThemePreference;
      label: string;
      icon: typeof Moon;
    }> = [
      { id: "light", label: "Light", icon: Sun },
      { id: "dark", label: "Dark", icon: Moon },
      { id: "system", label: "System", icon: Monitor },
    ];

    return (
      <div
        role="radiogroup"
        aria-label="Color theme preference"
        className={cn(
          fullWidth
            ? "grid w-full grid-cols-3 gap-0.5 rounded-full border border-white/[0.08] bg-[#101013] p-0.5"
            : "inline-grid max-w-full grid-cols-3 items-center gap-0.5 rounded-full border border-white/[0.08] bg-[#101013] p-0.5",
          className,
        )}
      >
        {items.map((item) => {
          const Icon = item.icon;
          const active = theme === item.id;
          return (
            <button
              key={item.id}
              type="button"
              role="radio"
              aria-checked={active}
              onClick={() => setTheme(item.id)}
              className={cn(
                "inline-flex h-6 min-w-0 items-center justify-center gap-1 rounded-full px-2 text-[11px] font-medium whitespace-nowrap transition-colors focus:outline-none focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[#2f71e3]",
                active
                  ? "bg-[#2f71e3] text-white"
                  : "text-zinc-400 hover:text-zinc-100",
              )}
            >
              <Icon className="h-3 w-3 shrink-0" />
              <span className="truncate">{item.label}</span>
            </button>
          );
        })}
      </div>
    );
  }

  const nextLabel = resolvedTheme === "dark" ? "light" : "dark";

  return (
    <button
      type="button"
      onClick={toggleTheme}
      aria-label={`Switch to ${nextLabel} mode`}
      title={`Switch to ${nextLabel} mode (current: ${theme})`}
      className={cn("vf-btn-ghost h-7 w-7 p-0", className)}
    >
      {resolvedTheme === "dark" ? (
        <Sun className="h-3.5 w-3.5 text-amber-300" />
      ) : (
        <Moon className="h-3.5 w-3.5 text-zinc-400" />
      )}
    </button>
  );
}
