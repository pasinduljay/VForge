"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { FormEvent, Suspense, useCallback, useEffect, useState } from "react";
import {
  ArrowRight,
  Building2,
  LogOut,
  Plus,
  Shield,
  ShieldCheck,
} from "lucide-react";
import { Badge, StatusBadge } from "@/components/ui/Badge";
import { Panel, SectionHeader } from "@/components/ui/Card";
import { PageHeader } from "@/components/ui/PageHeader";
import { EmptyState, NoticeBanner } from "@/components/ui/States";
import { ThemeToggle } from "@/components/ThemeProvider";
import { apiFetch, signOutAndRedirect } from "@/lib/api";
import {
  classifyOrganizationsError,
  type OrganizationsFailure,
} from "@/lib/organizations-state";
import type { AuthMe, Organization } from "@/lib/types";

function OrganizationsDirectoryContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const manageMode = searchParams.get("manage") === "1";

  const [auth, setAuth] = useState<AuthMe | null>(null);
  const [orgs, setOrgs] = useState<Organization[]>([]);
  const [loading, setLoading] = useState(true);
  const [autoEntering, setAutoEntering] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [failure, setFailure] = useState<OrganizationsFailure | null>(null);

  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const fetchAll = useCallback(async () => {
    const [me, orgList] = await Promise.all([
      apiFetch<AuthMe>("/api/v1/auth/me", {
        signal: AbortSignal.timeout(20_000),
      }),
      apiFetch<Organization[]>("/api/v1/organizations", {
        signal: AbortSignal.timeout(20_000),
      }),
    ]);
    return { me, orgList };
  }, []);

  const loadData = useCallback(async () => {
    setError(null);
    setFailure(null);
    try {
      const { me, orgList } = await fetchAll();
      setAuth(me);
      setOrgs(orgList);
      if (!manageMode && orgList.length === 1) {
        setAutoEntering(true);
        await apiFetch<AuthMe>("/api/v1/auth/switch-organization", {
          method: "POST",
          csrfToken: me.csrf_token,
          body: JSON.stringify({ organization_id: orgList[0].id }),
        }).catch(() => null);
        router.replace(`/organizations/${orgList[0].id}`);
      }
    } catch (err) {
      const classified = classifyOrganizationsError(err);
      setFailure(classified);
      setError(classified.message);
      if (classified.kind === "unauthenticated") {
        router.replace("/login");
      }
    } finally {
      setLoading(false);
    }
  }, [fetchAll, manageMode, router]);

  const handleRetry = useCallback(() => {
    setLoading(true);
    void loadData();
  }, [loadData]);

  useEffect(() => {
    let active = true;
    void fetchAll()
      .then(async ({ me, orgList }) => {
        if (!active) return;
        setAuth(me);
        setOrgs(orgList);
        setError(null);
        setFailure(null);

        if (!manageMode && orgList.length === 1) {
          setAutoEntering(true);
          await apiFetch<AuthMe>("/api/v1/auth/switch-organization", {
            method: "POST",
            csrfToken: me.csrf_token,
            body: JSON.stringify({ organization_id: orgList[0].id }),
          }).catch(() => null);
          if (active) {
            router.replace(`/organizations/${orgList[0].id}`);
          }
          return;
        }
        setLoading(false);
      })
      .catch((err) => {
        if (!active) return;
        const classified = classifyOrganizationsError(err);
        setFailure(classified);
        setError(classified.message);
        setLoading(false);
        if (classified.kind === "unauthenticated") {
          router.replace("/login");
        }
      });
    return () => {
      active = false;
    };
  }, [fetchAll, manageMode, router]);

  const handleSelectOrg = async (orgId: string) => {
    setError(null);
    try {
      await apiFetch<AuthMe>("/api/v1/auth/switch-organization", {
        method: "POST",
        csrfToken: auth?.csrf_token,
        body: JSON.stringify({ organization_id: orgId }),
      });
      router.push(`/organizations/${orgId}`);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to switch organization",
      );
    }
  };

  const handleCreateOrg = async (e: FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const created = await apiFetch<Organization>("/api/v1/organizations", {
        method: "POST",
        csrfToken: auth?.csrf_token,
        body: JSON.stringify({ name: name.trim(), slug: slug.trim() }),
      });
      setName("");
      setSlug("");
      router.push(`/organizations/${created.id}`);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to create organization",
      );
    } finally {
      setSubmitting(false);
    }
  };

  const handleSignOut = async () => {
    try {
      await signOutAndRedirect({
        csrfToken: auth?.csrf_token,
        onLocalRedirect: () => router.replace("/login"),
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to sign out");
    }
  };

  if (loading || autoEntering) {
    return (
      <main className="mx-auto max-w-3xl px-6 py-16 text-center text-sm text-zinc-400">
        {autoEntering
          ? "Opening your workspace dashboard..."
          : "Loading workspaces..."}
      </main>
    );
  }

  if (failure) {
    const isAuthRequired = failure.kind === "unauthenticated";
    return (
      <main className="mx-auto max-w-xl px-6 py-16">
        <div className="vf-surface rounded-2xl p-6 space-y-4">
          <div className="flex items-center justify-between gap-4">
            <h1 className="text-lg font-semibold text-white">
              {isAuthRequired ? "Redirecting to Sign In..." : failure.title}
            </h1>
            {failure.status !== null ? (
              <Badge tone="neutral">HTTP {failure.status}</Badge>
            ) : null}
          </div>
          <p className="text-xs leading-relaxed text-zinc-400">
            {isAuthRequired
              ? "Please sign in to access your VForge workspaces."
              : failure.message}
          </p>
          <div className="flex flex-wrap gap-2.5 pt-1">
            {isAuthRequired || failure.kind === "forbidden" ? (
              <Link
                href="/login"
                className="vf-btn-primary h-8 px-4 text-xs"
              >
                Go to Sign In
              </Link>
            ) : null}
            {!isAuthRequired ? (
              <button
                type="button"
                onClick={handleRetry}
                className="vf-btn-secondary h-8 px-4 text-xs"
              >
                Retry
              </button>
            ) : null}
            <Link
              href="/"
              className="vf-btn-secondary h-8 px-4 text-xs"
            >
              Back to Home
            </Link>
          </div>
        </div>
      </main>
    );
  }

  return (
    <div className="min-h-screen bg-[#09090b] text-zinc-100">
      <header className="border-b border-white/[0.06] bg-[#09090b]/92 backdrop-blur-md">
        <div className="mx-auto flex h-12 max-w-5xl items-center justify-between px-4 sm:px-6">
          <Link href="/" className="flex items-center gap-2.5">
            <div className="flex h-6 w-6 items-center justify-center rounded-md bg-white/[0.08] text-zinc-100">
              <Shield className="h-3.5 w-3.5" />
            </div>
            <span className="text-[13px] font-semibold tracking-tight text-white">
              VForge
            </span>
          </Link>
          <div className="flex items-center gap-2.5">
            <span className="hidden text-xs text-zinc-400 sm:inline">
              {auth?.user.display_name} ({auth?.user.email})
            </span>
            <ThemeToggle variant="icon" />
            <button
              type="button"
              onClick={() => void handleSignOut()}
              className="vf-btn-ghost h-8 px-2.5 text-xs"
            >
              <LogOut className="h-3.5 w-3.5" />
              Sign Out
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-5xl space-y-8 px-4 py-8 sm:px-6 sm:py-10">
        <PageHeader
          eyebrow="Workspaces & Tenants"
          title="Select or Create Workspace"
          description="Each organization acts as an isolated security account (similar to an AWS Account or GitHub Org) with its own projects, targets, and team roles."
        />

        {error ? <NoticeBanner tone="error" message={error} /> : null}

        <section className="space-y-4">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">
            Your Organizations ({orgs.length})
          </h2>

          {orgs.length === 0 ? (
            <EmptyState
              icon={<Building2 className="h-5 w-5" />}
              title="Create your first workspace"
              description="You do not belong to any organization yet. Create one below—for example, your team name or cloud environment—to start adding targets and running scans."
            />
          ) : (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {orgs.map((org) => {
                const summary = auth?.memberships.find(
                  (m) => m.organization_id === org.id,
                );
                const isActive = auth?.active_organization_id === org.id;
                return (
                  <Panel
                    key={org.id}
                    className="flex flex-col justify-between p-5 transition hover:border-white/[0.16]"
                  >
                    <div>
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex min-w-0 items-center gap-2.5">
                          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-white/[0.08] bg-[#19191e] text-zinc-300">
                            <Building2 className="h-4 w-4" />
                          </div>
                          <h3 className="truncate text-base font-semibold text-white">
                            {org.name}
                          </h3>
                        </div>
                        <Badge
                          tone={summary?.role === "owner" ? "info" : "neutral"}
                        >
                          {summary?.role || "member"}
                        </Badge>
                      </div>

                      <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-zinc-400">
                        <code className="rounded bg-[#131316] px-1.5 py-0.5 font-mono text-[11px] text-zinc-300">
                          {org.slug}
                        </code>
                        <StatusBadge status={org.status} />
                      </div>

                      {isActive && (
                        <div className="mt-3 inline-flex items-center gap-1.5 text-[11px] font-medium text-blue-400">
                          <ShieldCheck className="h-3.5 w-3.5" />
                          Active session workspace
                        </div>
                      )}
                    </div>

                    <div className="mt-5 border-t border-white/[0.06] pt-4">
                      <button
                        type="button"
                        onClick={() => void handleSelectOrg(org.id)}
                        className="vf-btn-primary h-9 w-full rounded-full px-4 text-xs"
                      >
                        Open Workspace
                        <ArrowRight className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </Panel>
                );
              })}
            </div>
          )}
        </section>

        <Panel>
          <SectionHeader
            title="Create New Organization"
            description="Optional: create a separate isolated workspace for another team or client."
          />
          <form
            onSubmit={handleCreateOrg}
            className="grid gap-4 sm:grid-cols-2"
          >
            <div>
              <label className="block text-xs font-medium text-zinc-300">
                Organization Name
              </label>
              <input
                type="text"
                required
                minLength={2}
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Cloud Platform Team"
                className="vf-input mt-1.5"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-zinc-300">
                URL Slug (lowercase, digits, hyphens)
              </label>
              <input
                type="text"
                required
                minLength={2}
                value={slug}
                onChange={(e) => setSlug(e.target.value)}
                placeholder="cloud-platform"
                className="vf-input mt-1.5"
              />
            </div>
            <div className="sm:col-span-2">
              <button
                type="submit"
                disabled={submitting}
                className="vf-btn-primary h-9 px-4 text-xs"
              >
                <Plus className="h-3.5 w-3.5" />
                {submitting ? "Creating..." : "Create Organization"}
              </button>
            </div>
          </form>
        </Panel>
      </main>
    </div>
  );
}

export default function OrganizationsPage() {
  return (
    <Suspense
      fallback={
        <main className="mx-auto max-w-3xl px-6 py-16 text-center text-sm text-zinc-400">
          Loading workspaces...
        </main>
      }
    >
      <OrganizationsDirectoryContent />
    </Suspense>
  );
}
