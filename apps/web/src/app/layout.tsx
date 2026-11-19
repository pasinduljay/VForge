import type { Metadata } from "next";
import { cookies, headers } from "next/headers";
import { connection } from "next/server";
import "@fontsource-variable/inter";
import "@fontsource-variable/jetbrains-mono";
import {
  ThemeProvider,
  type ResolvedTheme,
  type ThemePreference,
} from "@/components/ThemeProvider";
import "./globals.css";

export const metadata: Metadata = {
  title: "VForge — Cloud & Application Security Control Plane",
  description:
    "Self-hosted security testing control plane with guided cloud-engineer workflows, scope isolation, and OIDC RBAC.",
};

const THEME_INIT_SCRIPT = `(function(){try{var d=document.documentElement;var s=localStorage.getItem('vforge-theme');var p=(s==='light'||s==='dark'||s==='system')?s:(d.getAttribute('data-theme-preference')||'dark');var r=p==='system'?(window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'):p;d.setAttribute('data-theme',r);d.setAttribute('data-theme-preference',p);d.classList.toggle('dark',r==='dark');d.classList.toggle('light',r==='light');d.style.colorScheme=r;}catch(e){}})();`;

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  await connection();
  const [cookieStore, headerStore] = await Promise.all([cookies(), headers()]);
  const rawCookie = cookieStore.get("vforge_theme")?.value;
  const initialPref: ThemePreference =
    rawCookie === "light" || rawCookie === "dark" || rawCookie === "system"
      ? rawCookie
      : "dark";
  const initialResolved: ResolvedTheme =
    initialPref === "light" ? "light" : "dark";
  const nonce = headerStore.get("x-nonce") ?? undefined;

  return (
    <html
      lang="en"
      data-theme={initialResolved}
      data-theme-preference={initialPref}
      className={initialResolved}
      suppressHydrationWarning
    >
      <head>
        <script
          nonce={nonce}
          suppressHydrationWarning
          dangerouslySetInnerHTML={{ __html: THEME_INIT_SCRIPT }}
        />
      </head>
      <body className="min-h-screen bg-[var(--vf-bg-canvas)] text-[var(--vf-text-primary)] font-sans antialiased selection:bg-blue-500/30 selection:text-white">
        <ThemeProvider initialPreference={initialPref}>
          {children}
        </ThemeProvider>
      </body>
    </html>
  );
}
