"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ArrowRight, CheckCircle2, Lock, Server } from "lucide-react";
import { StatusBadge } from "@/components/ui/Badge";
import { apiFetch } from "@/lib/api";
import type { AuthMe, PlatformMeta } from "@/lib/types";

export function PlatformStatusCard() {
  const [meta, setMeta] = useState<PlatformMeta | null>(null);
  const [auth, setAuth] = useState<AuthMe | null>(null);
  const [error, setError] = useState<string | null>(null);

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
      .catch((err: unknown) => {
        if (!active) return;
        setError(
          err instanceof Error ? err.message : "Failed to load platform metadata",
        );
      });
    return () => {
      active = false;
    };
  }, []);

  if (error) {
    return (
      <div className="rounded-2xl border border-white/[0.08] bg-[#131317] p-5 text-xs text-zinc-300">
        Control-plane status unavailable: {error}
      </div>
    );
  }

  if (!meta) {
    return (
      <div className="h-36 animate-pulse rounded-2xl border border-white/[0.068] bg-[#141417] p-5" />
    );
  }

  const workspaceHref =
    auth?.active_organization_id
      ? `/organizations/${auth.active_organization_id}`
      : auth?.memberships.length === 1
        ? `/organizations/${auth.memberships[0].organization_id}`
        : "/organizations";

  return (
    <div className="vf-surface rounded-2xl p-5">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.06] pb-3.5">
        <div className="flex items-center gap-2.5">
          <Server className="h-4 w-4 text-zinc-400" />
          <div>
            <h2 className="text-sm font-semibold text-zinc-100">
              Control Plane Telemetry
            </h2>
            <p className="text-[11px] text-zinc-500">
              {meta.platform} v{meta.version} · Phase {meta.phase}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <StatusBadge status={meta.environment} />
          <span className="text-[11px] font-medium text-zinc-400">
            {meta.oidc_enabled ? "OIDC SSO Ready" : "OIDC Disabled"}
          </span>
        </div>
      </div>

      <dl className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-white/[0.06] bg-[#0e0e11] p-3">
          <dt className="text-[11px] text-zinc-500">API Isolation</dt>
          <dd className="mt-1 flex items-center gap-1.5 text-xs font-medium text-emerald-300">
            <Lock className="h-3.5 w-3.5" />
            {meta.docker_socket_mounted
              ? "Socket Mounted"
              : "No Docker Socket"}
          </dd>
        </div>
        <div className="rounded-xl border border-white/[0.06] bg-[#0e0e11] p-3">
          <dt className="text-[11px] text-zinc-500">Scanners</dt>
          <dd className="mt-1 text-xs font-medium text-zinc-200">
            {meta.scanners_enabled ? "Enabled" : "Standby"}
          </dd>
        </div>
        <div className="rounded-xl border border-white/[0.06] bg-[#0e0e11] p-3">
          <dt className="text-[11px] text-zinc-500">Runner Agents</dt>
          <dd className="mt-1 text-xs font-medium text-zinc-200">
            {meta.runner_connected ? "Connected" : "Awaiting Runner"}
          </dd>
        </div>
        <div className="rounded-xl border border-white/[0.06] bg-[#0e0e11] p-3">
          <dt className="text-[11px] text-zinc-500">Modules Ready</dt>
          <dd className="mt-1 flex items-center gap-1.5 text-xs font-medium text-zinc-100 tabular-nums">
            <CheckCircle2 className="h-3.5 w-3.5 text-blue-400" />
            {meta.implemented_capabilities.length} modules
          </dd>
        </div>
      </dl>

      <div className="mt-4 flex flex-wrap items-center justify-between gap-2 border-t border-white/[0.06] pt-3 text-xs text-zinc-500">
        {auth ? (
          <span>
            Signed in as{" "}
            <strong className="text-zinc-200">{auth.user.display_name}</strong>
          </span>
        ) : (
          <span>Sign in with your Keycloak account to access your workspace</span>
        )}
        <Link
          href={auth ? workspaceHref : "/login"}
          className="inline-flex items-center gap-1 font-medium text-blue-400 hover:text-blue-300"
        >
          {auth ? "Open Workspace" : "Sign In"}
          <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      </div>
    </div>
  );
}
