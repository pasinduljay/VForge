"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ArrowRight, Check, Copy, Shield, ShieldCheck } from "lucide-react";
import { NoticeBanner } from "@/components/ui/States";
import { ThemeToggle } from "@/components/ThemeProvider";
import { apiFetch, signOutAndRedirect } from "@/lib/api";
import type { AuthMe, PlatformMeta } from "@/lib/types";

export default function LoginPage() {
  const [meta, setMeta] = useState<PlatformMeta | null>(null);
  const [auth, setAuth] = useState<AuthMe | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [signingOut, setSigningOut] = useState(false);
  const [redirectingOidc, setRedirectingOidc] = useState(false);
  const [copiedUser, setCopiedUser] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    void Promise.all([
      apiFetch<PlatformMeta>("/api/v1/meta"),
      apiFetch<AuthMe>("/api/v1/auth/me").catch(() => null),
    ])
      .then(([metaData, authData]) => {
        if (!active) return;
        setMeta(metaData);
        setAuth(authData);
      })
      .catch((err) => {
        if (!active) return;
        setStatusError(
          err instanceof Error ? err.message : "Failed to inspect auth status",
        );
      });
    return () => {
      active = false;
    };
  }, []);

  const handleOidcLogin = async () => {
    setRedirectingOidc(true);
    setStatusError(null);
    try {
      const data = await apiFetch<{ authorization_url: string }>(
        "/api/v1/auth/oidc/login?mode=json&prompt=login",
      );
      window.location.assign(data.authorization_url);
    } catch (err) {
      setStatusError(
        err instanceof Error ? err.message : "Failed to initiate OIDC login",
      );
      setRedirectingOidc(false);
    }
  };

  const handleSignOut = async () => {
    setSigningOut(true);
    setStatusError(null);
    try {
      const { navigated } = await signOutAndRedirect({
        csrfToken: auth?.csrf_token,
      });
      if (!navigated) {
        setAuth(null);
      }
    } catch (err) {
      setStatusError(err instanceof Error ? err.message : "Sign out failed");
    } finally {
      setSigningOut(false);
    }
  };

  const handleCopy = (email: string) => {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      void navigator.clipboard.writeText(email).then(() => {
        setCopiedUser(email);
        setTimeout(() => setCopiedUser(null), 1800);
      });
    }
  };

  const directWorkspaceHref =
    auth?.active_organization_id
      ? `/organizations/${auth.active_organization_id}`
      : auth?.memberships.length === 1
        ? `/organizations/${auth.memberships[0].organization_id}`
        : "/organizations";

  return (
    <div className="flex min-h-screen flex-col justify-between bg-[#09090b] px-6 py-10 text-zinc-100">
      <div className="mx-auto w-full max-w-[440px]">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <Link
            href="/"
            className="inline-flex items-center gap-1.5 text-xs text-zinc-500 transition hover:text-zinc-200"
          >
            ← Back to home
          </Link>
          <ThemeToggle variant="segmented" />
        </div>

        <div className="vf-dock mt-5 rounded-2xl p-6 sm:p-7">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-white/[0.08] text-zinc-100">
                <Shield className="h-4.5 w-4.5" />
              </div>
              <div>
                <h1 className="text-lg font-semibold tracking-tight text-white">
                  Sign in to VForge
                </h1>
                <p className="text-xs text-zinc-400">
                  Local SSO via Keycloak (127.0.0.1:8080)
                </p>
              </div>
            </div>
            {meta ? (
              <span className="text-[11px] font-medium text-zinc-500">
                {meta.oidc_enabled ? "OIDC Active" : "OIDC Off"}
              </span>
            ) : null}
          </div>

          {statusError ? (
            <div className="mt-5">
              <NoticeBanner tone="error" message={statusError} />
            </div>
          ) : null}

          {auth ? (
            <div className="mt-6 space-y-4 border-t border-white/[0.06] pt-5">
              <div className="flex items-center gap-2.5 text-xs text-zinc-300">
                <ShieldCheck className="h-4 w-4 text-emerald-400" />
                <span>
                  Signed in as <strong className="text-white">{auth.user.display_name}</strong>{" "}
                  ({auth.user.email})
                </span>
              </div>

              <div className="flex items-center gap-2.5 pt-1">
                <Link
                  href={directWorkspaceHref}
                  className="vf-btn-primary h-9 flex-1 rounded-full px-4 text-xs"
                >
                  Open Dashboard
                  <ArrowRight className="h-3.5 w-3.5" />
                </Link>
                <Link
                  href="/organizations?manage=1"
                  className="vf-btn-secondary h-9 px-3.5 text-xs"
                >
                  Manage Orgs
                </Link>
              </div>

              <button
                type="button"
                onClick={() => void handleSignOut()}
                disabled={signingOut}
                className="vf-btn-ghost h-8 w-full text-xs text-zinc-400"
              >
                {signingOut ? "Signing out..." : "Sign out and switch account"}
              </button>
            </div>
          ) : (
            <div className="mt-6 space-y-5 border-t border-white/[0.06] pt-5">
              {meta && !meta.oidc_enabled ? (
                <NoticeBanner
                  tone="warning"
                  title="OIDC Provider Not Enabled"
                  message="Start Docker Compose with --profile dev-oidc and set OIDC_ENABLED=true in .env to enable browser login."
                />
              ) : (
                <>
                  <p className="text-[13px] leading-relaxed text-zinc-400">
                    Clicking below opens Keycloak where you enter a local account. Once verified, you go straight to your workspace.
                  </p>

                  <div className="overflow-hidden rounded-xl border border-white/[0.07] bg-[#0e0e11] divide-y divide-white/[0.06]">
                    {[
                      {
                        label: "Workspace Owner (Full access)",
                        email: "dev-owner@vforge.local",
                      },
                      {
                        label: "Security Analyst (Read & triage)",
                        email: "dev-analyst@vforge.local",
                      },
                    ].map((acct) => (
                      <div
                        key={acct.email}
                        className="flex items-center justify-between gap-2 px-3.5 py-2.5"
                      >
                        <div className="min-w-0">
                          <div className="text-[11px] text-zinc-500">
                            {acct.label}
                          </div>
                          <div className="truncate font-mono text-xs text-zinc-100">
                            {acct.email}
                          </div>
                        </div>
                        <button
                          type="button"
                          onClick={() => handleCopy(acct.email)}
                          className="vf-btn-secondary h-7 px-2.5 text-[11px]"
                        >
                          {copiedUser === acct.email ? (
                            <>
                              <Check className="h-3 w-3 text-emerald-400" />
                              Copied
                            </>
                          ) : (
                            <>
                              <Copy className="h-3 w-3" />
                              Copy Email
                            </>
                          )}
                        </button>
                      </div>
                    ))}
                  </div>

                  <p className="text-[11px] leading-relaxed text-zinc-500">
                    Local password is stored in{" "}
                    <span className="font-mono text-zinc-300">
                      infrastructure/keycloak/realm-vforge.json
                    </span>{" "}
                    under <span className="font-mono text-zinc-300">dev-owner</span>. Press{" "}
                    <span className="text-zinc-300">Esc</span> if a password manager overlay covers the input.
                  </p>
                </>
              )}

              <button
                type="button"
                onClick={() => void handleOidcLogin()}
                disabled={redirectingOidc || (meta ? !meta.oidc_enabled : false)}
                className="vf-btn-primary h-10 w-full rounded-full text-[13px]"
              >
                {redirectingOidc ? "Opening Keycloak..." : "Continue to Sign In (OIDC)"}
                <ArrowRight className="h-3.5 w-3.5" />
              </button>
            </div>
          )}
        </div>
      </div>

      <footer className="mx-auto mt-8 w-full max-w-[440px] text-center text-[11px] text-zinc-600">
        PostgreSQL RLS tenant isolation &amp; least-privilege RBAC enforced
      </footer>
    </div>
  );
}
