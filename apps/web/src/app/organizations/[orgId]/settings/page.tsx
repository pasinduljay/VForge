"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { FormEvent, useCallback, useEffect, useState } from "react";
import {
  Building2,
  ChevronDown,
  ChevronRight,
  KeyRound,
  Lock,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";
import OrgShell, { hasPermission } from "@/components/OrgShell";
import { Badge, StatusBadge } from "@/components/ui/Badge";
import { PageHeader } from "@/components/ui/PageHeader";
import { NoticeBanner } from "@/components/ui/States";
import { ThemeToggle, useTheme } from "@/components/ThemeProvider";
import { apiFetch, formatUtc } from "@/lib/api";
import type {
  AuthMe,
  Organization,
  OrganizationMembershipSummary,
} from "@/lib/types";

function SettingsContent({
  orgId,
  auth,
  membership,
  reloadAuth,
}: {
  orgId: string;
  auth: AuthMe;
  membership: OrganizationMembershipSummary | null;
  reloadAuth: () => Promise<void>;
}) {
  const [org, setOrg] = useState<Organization | null>(null);
  const [nameInput, setNameInput] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [rotating, setRotating] = useState(false);
  const [showPermissions, setShowPermissions] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const { theme, resolvedTheme } = useTheme();

  const canUpdateOrg = hasPermission(membership, "org:update");

  const loadOrg = useCallback(async () => {
    try {
      const data = await apiFetch<Organization>(`/api/v1/organizations/${orgId}`);
      setOrg(data);
      setNameInput(data.name);
      setError(null);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to load organization settings",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId]);

  useEffect(() => {
    let active = true;
    void Promise.resolve().then(() => {
      if (active) return loadOrg();
    });
    return () => {
      active = false;
    };
  }, [loadOrg]);

  const handleSaveName = async (e: FormEvent) => {
    e.preventDefault();
    if (!canUpdateOrg) return;
    setSaving(true);
    setError(null);
    setNotice(null);
    try {
      const updated = await apiFetch<Organization>(
        `/api/v1/organizations/${orgId}`,
        {
          method: "PATCH",
          csrfToken: auth.csrf_token,
          body: JSON.stringify({ name: nameInput.trim() }),
        },
      );
      setOrg(updated);
      setNameInput(updated.name);
      setNotice("Organization profile updated and audited.");
      await reloadAuth();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to update organization",
      );
    } finally {
      setSaving(false);
    }
  };

  const handleRotateSession = async () => {
    setRotating(true);
    setError(null);
    setNotice(null);
    try {
      await apiFetch("/api/v1/auth/session/rotate", {
        method: "POST",
        csrfToken: auth.csrf_token,
      });
      await reloadAuth();
      setNotice("Session token and CSRF binding rotated successfully.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Session rotation failed");
    } finally {
      setRotating(false);
    }
  };

  return (
    <div className="mx-auto max-w-4xl space-y-8">
      <PageHeader
        eyebrow="Administration"
        title="Organization & Session Settings"
        description="Manage tenant identity metadata, inspect effective RBAC permissions, and rotate session credentials."
      />

      {error && <NoticeBanner tone="error" message={error} />}
      {notice && <NoticeBanner tone="success" message={notice} />}

      {/* Appearance & Color Theme */}
      <section className="space-y-3">
        <div>
          <h2 className="text-[14px] font-medium text-[#f4f4f5]">
            Appearance &amp; Theme Preference
          </h2>
          <p className="mt-0.5 text-xs text-[#71717a]">
            Choose between Obsidian Dark, Alabaster Light, or automatic OS system synchronization across all views.
          </p>
        </div>

        <div className="overflow-hidden rounded-[14px] border border-white/[0.068] bg-[#141417]/90 px-5 py-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <div className="flex items-center gap-2 text-[13px] font-medium text-[#f4f4f5]">
                <span>Interface Color Mode</span>
                <Badge tone="neutral" className="capitalize">
                  {theme} ({resolvedTheme})
                </Badge>
              </div>
              <div className="mt-0.5 text-xs text-[#71717a]">
                Persisted locally and applied before first paint with zero theme flash.
              </div>
            </div>
            <ThemeToggle variant="segmented" className="w-full sm:w-auto" />
          </div>
        </div>
      </section>

      {/* Organization Profile (VForge Studio grouped hairline settings layout) */}
      <section className="space-y-3">
        <div>
          <h2 className="text-[14px] font-medium text-[#f4f4f5]">
            Organization Profile
          </h2>
          <p className="mt-0.5 text-xs text-[#71717a]">
            Changes write an immutable audit entry and update navigation across active tenant sessions.
          </p>
        </div>

        {loading && !org ? (
          <div className="h-44 animate-pulse rounded-[14px] border border-white/[0.068] bg-[#141417]/80" />
        ) : org ? (
          <form onSubmit={handleSaveName} className="vf-dock p-1">
            <div className="divide-y divide-white/[0.068] overflow-hidden rounded-[14px] bg-[#141417]/90">
              <div className="flex flex-col gap-3 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <div className="text-[13px] font-medium text-[#f4f4f5]">
                    Organization Name
                  </div>
                  <div className="mt-0.5 text-xs text-[#71717a]">
                    Displayed in the workspace switcher and compliance exports.
                  </div>
                </div>
                <div className="flex items-center gap-2 sm:w-80 sm:justify-end">
                  <input
                    type="text"
                    required
                    minLength={2}
                    disabled={!canUpdateOrg || saving}
                    value={nameInput}
                    onChange={(e) => setNameInput(e.target.value)}
                    aria-label="Organization Name"
                    className="w-full rounded-lg border border-white/[0.09] bg-[#101013] px-3 py-1.5 text-[13px] text-[#f4f4f5] placeholder-[#71717a] focus:border-[#3b72f2] focus:outline-none disabled:opacity-60"
                  />
                  {canUpdateOrg && (
                    <button
                      type="submit"
                      disabled={saving}
                      className="vf-btn-primary shrink-0 px-4 py-1.5 text-xs font-medium"
                    >
                      {saving ? "Saving..." : "Save"}
                    </button>
                  )}
                </div>
              </div>

              <div className="flex flex-col gap-2 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <div className="text-[13px] font-medium text-[#f4f4f5]">
                    Immutable Tenant Slug &amp; ID
                  </div>
                  <div className="mt-0.5 text-xs text-[#71717a]">
                    Bound to Row-Level Security policies and API resource routes.
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <code className="rounded-full border border-white/[0.08] bg-[#1c1c20] px-3 py-1 font-mono text-[#d4d4d8]">
                    {org.slug}
                  </code>
                  <code className="rounded-full border border-white/[0.068] bg-[#101013] px-3 py-1 font-mono text-[11px] text-[#a1a1aa]">
                    {org.id}
                  </code>
                </div>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5 text-xs">
                <div className="flex items-center gap-2 text-[#a1a1aa]">
                  <Building2 className="h-3.5 w-3.5 text-[#71717a]" />
                  <span>Tenant status &amp; provisioning timestamp</span>
                </div>
                <div className="flex items-center gap-3">
                  <StatusBadge status={org.status} />
                  <span className="text-[#71717a]">
                    Created {formatUtc(org.created_at)}
                  </span>
                </div>
              </div>
            </div>
            {!canUpdateOrg && (
              <div className="px-4 py-3">
                <NoticeBanner
                  tone="info"
                  message="Only users with org:update permission (Owner or Admin) can modify organization settings."
                />
              </div>
            )}
          </form>
        ) : null}
      </section>

      {/* Session & Identity */}
      <section className="space-y-3">
        <div>
          <h2 className="text-[14px] font-medium text-[#f4f4f5]">
            Authenticated Session &amp; Access
          </h2>
          <p className="mt-0.5 text-xs text-[#71717a]">
            OIDC-backed session identity, CSRF binding, and effective RBAC capabilities.
          </p>
        </div>

        <div className="overflow-hidden rounded-[14px] border border-white/[0.068] bg-[#141417]/90 divide-y divide-white/[0.068]">
          <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-4">
            <div>
              <div className="text-[13px] font-medium text-[#f4f4f5]">
                Signed-in Identity
              </div>
              <div className="mt-0.5 font-mono text-xs text-[#71717a]">
                {auth.user.email} · {auth.user.oidc_subject}
              </div>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-medium text-[#e4e4e7]">
                {auth.user.display_name}
              </span>
              <Badge tone="info">{membership?.role ?? "member"}</Badge>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-4">
            <div>
              <div className="text-[13px] font-medium text-[#f4f4f5]">
                Session Token &amp; CSRF Binding
              </div>
              <div className="mt-0.5 text-xs text-[#71717a]">
                Rotate HTTP-only session credentials immediately without re-authenticating.
              </div>
            </div>
            <button
              type="button"
              onClick={() => void handleRotateSession()}
              disabled={rotating}
              className="vf-btn-secondary h-8 px-3.5 text-xs"
            >
              <RefreshCw
                className={`h-3.5 w-3.5 ${rotating ? "animate-spin" : ""}`}
              />
              {rotating ? "Rotating..." : "Rotate Session"}
            </button>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-4">
            <div>
              <div className="text-[13px] font-medium text-[#f4f4f5]">
                Tenant Members &amp; Approvals
              </div>
              <div className="mt-0.5 text-xs text-[#71717a]">
                Assign workspace roles and add a second approver for Separation of Duties.
              </div>
            </div>
            <Link
              href={`/organizations/${orgId}/members`}
              className="vf-btn-secondary h-8 px-3.5 text-xs"
            >
              Manage Members →
            </Link>
          </div>

          <div>
            <button
              type="button"
              onClick={() => setShowPermissions((prev) => !prev)}
              className="flex w-full items-center justify-between px-5 py-3.5 text-left transition hover:bg-white/[0.02]"
            >
              <span className="inline-flex items-center gap-2 text-xs font-medium text-[#a1a1aa]">
                <ShieldCheck className="h-3.5 w-3.5 text-[#3b72f2]" />
                Effective RBAC Permissions ({(membership?.permissions ?? []).length} capabilities for{" "}
                {membership?.role ?? "member"})
              </span>
              <span className="inline-flex items-center gap-1 text-xs text-[#71717a]">
                {showPermissions ? "Hide" : "Advanced"}
                {showPermissions ? (
                  <ChevronDown className="h-3.5 w-3.5" />
                ) : (
                  <ChevronRight className="h-3.5 w-3.5" />
                )}
              </span>
            </button>
            {showPermissions && (
              <div className="border-t border-white/[0.068] bg-[#101013]/80 px-5 py-4">
                <div className="flex flex-wrap gap-1.5">
                  {(membership?.permissions ?? []).map((perm) => (
                    <span
                      key={perm}
                      className="inline-flex items-center gap-1.5 rounded-md border border-white/[0.07] bg-[#16161a] px-2.5 py-1 font-mono text-[11px] text-[#d4d4d8]"
                    >
                      <span className="h-1.5 w-1.5 rounded-full bg-[#3b72f2]" />
                      {perm}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Planned Org Governance Settings */}
      <section className="space-y-3">
        <div className="flex items-center justify-between gap-2">
          <div>
            <h2 className="text-[14px] font-medium text-[#f4f4f5]">
              Planned Tenant Policy &amp; Retention Settings
            </h2>
            <p className="mt-0.5 text-xs text-[#71717a]">
              Additional organization-level controls tracked for future backend schema and API support.
            </p>
          </div>
          <Badge tone="planned">Backend Planned</Badge>
        </div>

        <div className="grid gap-3 sm:grid-cols-3 text-xs">
          <div className="rounded-[14px] border border-white/[0.068] bg-[#141417]/70 p-4 space-y-1.5">
            <div className="flex items-center gap-2 font-medium text-[#e4e4e7]">
              <KeyRound className="h-3.5 w-3.5 text-[#71717a]" />
              Custom SLA Windows
            </div>
            <p className="text-[#71717a] leading-relaxed">
              Configurable default SLA deadlines by severity level (currently driven by system policy defaults).
            </p>
          </div>
          <div className="rounded-[14px] border border-white/[0.068] bg-[#141417]/70 p-4 space-y-1.5">
            <div className="flex items-center gap-2 font-medium text-[#e4e4e7]">
              <Lock className="h-3.5 w-3.5 text-[#71717a]" />
              Data &amp; Artifact Retention
            </div>
            <p className="text-[#71717a] leading-relaxed">
              Automated tenant retention schedules for encrypted artifacts and closed scan records.
            </p>
          </div>
          <div className="rounded-[14px] border border-white/[0.068] bg-[#141417]/70 p-4 space-y-1.5">
            <div className="flex items-center gap-2 font-medium text-[#e4e4e7]">
              <ShieldCheck className="h-3.5 w-3.5 text-[#71717a]" />
              SSO Domain Enforcement
            </div>
            <p className="text-[#71717a] leading-relaxed">
              Per-tenant OIDC domain allow-lists and automatic role mapping from IdP groups.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}

export default function OrganizationSettingsPage() {
  const params = useParams<{ orgId: string }>();
  const orgId = params.orgId;

  return (
    <OrgShell orgId={orgId}>
      {({ auth, membership, reloadAuth }) => (
        <SettingsContent
          orgId={orgId}
          auth={auth}
          membership={membership}
          reloadAuth={reloadAuth}
        />
      )}
    </OrgShell>
  );
}
