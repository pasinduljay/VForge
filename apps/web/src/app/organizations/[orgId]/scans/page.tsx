"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { FormEvent, useCallback, useEffect, useState } from "react";
import OrgShell, { hasPermission } from "@/components/OrgShell";
import { Select } from "@/components/ui/Select";
import { apiFetch, formatUtc } from "@/lib/api";
import type {
  Authorization,
  Environment,
  PaginatedResponse,
  Project,
  RunnerPool,
  ScanProfile,
  ScanRunDetail,
  ScanRunSummary,
  ScanTargetLease,
  ScopeSnapshot,
} from "@/lib/types";

const TERMINAL_RUN_STATUSES = new Set([
  "completed",
  "completed_with_errors",
  "partial",
  "failed",
  "rejected",
  "cancelled",
]);

function ScansConsoleContent({
  orgId,
  canStartScan,
  canCancelScan,
  csrfToken,
}: {
  orgId: string;
  canStartScan: boolean;
  canCancelScan: boolean;
  csrfToken: string | null;
}) {
  const [scans, setScans] = useState<ScanRunSummary[]>([]);
  const [leases, setLeases] = useState<ScanTargetLease[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [environments, setEnvironments] = useState<Environment[]>([]);
  const [profiles, setProfiles] = useState<ScanProfile[]>([]);
  const [authorizations, setAuthorizations] = useState<Authorization[]>([]);
  const [snapshots, setSnapshots] = useState<ScopeSnapshot[]>([]);
  const [runnerPools, setRunnerPools] = useState<RunnerPool[]>([]);

  const [projectId, setProjectId] = useState("");
  const [environmentId, setEnvironmentId] = useState("");
  const [scanProfileId, setScanProfileId] = useState("");
  const [authorizationId, setAuthorizationId] = useState("");
  const [snapshotId, setSnapshotId] = useState("");
  const [executionMode, setExecutionMode] = useState<"simulated" | "runner">("simulated");
  const [targetPoolId, setTargetPoolId] = useState("");
  const [revalidateDns, setRevalidateDns] = useState(true);

  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    const [scansRes, leasesRes, projRes, profRes, authRes, snapRes, poolsRes] =
      await Promise.all([
        apiFetch<PaginatedResponse<ScanRunSummary>>(
          `/api/v1/organizations/${orgId}/scans?limit=50`,
        ),
        apiFetch<ScanTargetLease[]>(
          `/api/v1/organizations/${orgId}/leases?limit=50`,
        ).catch(() => [] as ScanTargetLease[]),
        apiFetch<PaginatedResponse<Project>>(
          `/api/v1/organizations/${orgId}/projects?limit=100`,
        ),
        apiFetch<PaginatedResponse<ScanProfile>>(
          `/api/v1/organizations/${orgId}/scan-profiles?limit=100`,
        ),
        apiFetch<PaginatedResponse<Authorization>>(
          `/api/v1/organizations/${orgId}/authorizations?limit=100`,
        ),
        apiFetch<PaginatedResponse<ScopeSnapshot>>(
          `/api/v1/organizations/${orgId}/snapshots?limit=100`,
        ).catch(() => ({ items: [] as ScopeSnapshot[], total: 0, limit: 100, offset: 0 })),
        apiFetch<RunnerPool[]>(
          `/api/v1/organizations/${orgId}/runner-pools`,
        ).catch(() => [] as RunnerPool[]),
      ]);
    return { scansRes, leasesRes, projRes, profRes, authRes, snapRes, poolsRes };
  }, [orgId]);

  const applyData = useCallback(
    (data: Awaited<ReturnType<typeof fetchData>>) => {
      setScans(data.scansRes.items);
      setLeases(data.leasesRes);
      setProjects(data.projRes.items);
      setProfiles(data.profRes.items);
      setRunnerPools(data.poolsRes);
      if (data.poolsRes.length > 0) {
        setTargetPoolId((prev) => prev || data.poolsRes[0].id);
      }
      const approvedAuths = data.authRes.items.filter(
        (item) => item.status === "approved",
      );
      setAuthorizations(approvedAuths);
      setSnapshots(data.snapRes.items);
      if (data.projRes.items.length > 0) {
        setProjectId((prev) => prev || data.projRes.items[0].id);
      }
      if (data.profRes.items.length > 0) {
        setScanProfileId((prev) => prev || data.profRes.items[0].id);
      }
      if (approvedAuths.length > 0) {
        const defaultAuthId = approvedAuths[0].id;
        setAuthorizationId((prev) => prev || defaultAuthId);
        const matchingSnap = data.snapRes.items.find(
          (s) => s.authorization_id === defaultAuthId,
        );
        if (matchingSnap) {
          setSnapshotId((prev) => prev || matchingSnap.id);
        }
      }
      setError(null);
      setLoading(false);
    },
    [],
  );

  const reload = useCallback(async () => {
    try {
      const data = await fetchData();
      applyData(data);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to load scan orchestration state",
      );
      setLoading(false);
    }
  }, [fetchData, applyData]);

  useEffect(() => {
    let active = true;
    void fetchData()
      .then((data) => {
        if (!active) return;
        applyData(data);
      })
      .catch((err) => {
        if (!active) return;
        setError(
          err instanceof Error ? err.message : "Failed to load scan orchestration state",
        );
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [fetchData, applyData]);

  useEffect(() => {
    if (!projectId) {
      return;
    }
    let active = true;
    void apiFetch<PaginatedResponse<Environment>>(
      `/api/v1/organizations/${orgId}/projects/${projectId}/environments?limit=100`,
    )
      .then((res) => {
        if (!active) return;
        setEnvironments(res.items);
        if (res.items.length > 0) {
          setEnvironmentId((prev) =>
            res.items.some((e) => e.id === prev) ? prev : res.items[0].id,
          );
        } else {
          setEnvironmentId("");
        }
      })
      .catch(() => {
        if (!active) return;
        setEnvironments([]);
      });
    return () => {
      active = false;
    };
  }, [orgId, projectId]);

  const matchingSnapshots = snapshots.filter(
    (s) => !authorizationId || s.authorization_id === authorizationId,
  );
  const resolvedSnapshotId = matchingSnapshots.some((s) => s.id === snapshotId)
    ? snapshotId
    : (matchingSnapshots[0]?.id ?? "");

  const handleCreateScan = async (evt: FormEvent) => {
    evt.preventDefault();
    setSubmitting(true);
    setError(null);
    setNotice(null);
    try {
      const idempotencyKey =
        typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
          ? crypto.randomUUID()
          : `scan-${Date.now()}`;
      const created = await apiFetch<ScanRunDetail>(
        `/api/v1/organizations/${orgId}/scans`,
        {
          method: "POST",
          csrfToken,
          headers: {
            "Idempotency-Key": idempotencyKey,
          },
          body: JSON.stringify({
            project_id: projectId,
            environment_id: environmentId,
            scan_profile_id: scanProfileId,
            authorization_id: authorizationId,
            scope_snapshot_id: resolvedSnapshotId,
            execution_mode: executionMode,
            target_pool_id: executionMode === "runner" && targetPoolId ? targetPoolId : null,
            revalidate_dns: revalidateDns,
          }),
        },
      );
      setNotice(
        `Queued ${executionMode} orchestration run ${created.id.slice(0, 8)} (${created.stages.length} stages).`,
      );
      await reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to enqueue scan run");
    } finally {
      setSubmitting(false);
    }
  };

  const handleCancel = async (scanId: string) => {
    setError(null);
    setNotice(null);
    try {
      const updated = await apiFetch<ScanRunDetail>(
        `/api/v1/organizations/${orgId}/scans/${scanId}/cancel`,
        {
          method: "POST",
          csrfToken,
          body: JSON.stringify({ reason: "Cancelled from Scans console" }),
        },
      );
      setNotice(`Scan run ${updated.id.slice(0, 8)} status is now ${updated.status}.`);
      await reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to cancel scan run");
    }
  };

  return (
    <div className="space-y-6">
      <div className="vf-surface rounded-2xl border-blue-500/20 p-5 text-sm text-zinc-200">
        <div className="text-[11px] font-semibold uppercase tracking-[0.12em] text-blue-400">
          Step 4 of 6 · Run Security Checks
        </div>
        <div className="mt-1 font-semibold text-white">
          Scan Center — Automated App, Code, Container &amp; Network Checks
        </div>
        <p className="mt-1 text-xs text-zinc-400">
          Pick an approved target below to start a security scan. Scans run in isolated containers with rate limits and safety checks — you don&apos;t need to configure tool flags unless you want to.
        </p>
      </div>

      {error && (
        <div className="rounded-md border border-white/[0.08] bg-[#131317] px-4 py-3 text-sm text-zinc-200">
          {error}
        </div>
      )}
      {notice && (
        <div className="rounded-md border border-white/[0.08] bg-[#121614] px-4 py-3 text-sm text-zinc-200">
          {notice}
        </div>
      )}

      {canStartScan && (
        <form
          onSubmit={handleCreateScan}
          className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-5 space-y-4"
        >
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-white">
              Launch Orchestration Run
            </h2>
            <button
              type="button"
              onClick={() => void reload()}
              className="vf-btn-secondary px-3 py-1 text-xs"
            >
              Refresh State
            </button>
          </div>
          {(projects.length === 0 ||
            environments.length === 0 ||
            profiles.length === 0 ||
            authorizations.length === 0) && (
            <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-white/[0.08] bg-[#131317] px-4 py-3 text-xs text-zinc-200">
              <span>
                Complete prerequisites before launching:{" "}
                {projects.length === 0 || environments.length === 0
                  ? "create a project & environment"
                  : profiles.length === 0
                    ? "create a scan profile"
                    : "approve at least one testing authorization (Step 3)"}
                .
              </span>
              <div className="flex flex-wrap gap-2">
                {(projects.length === 0 || environments.length === 0) && (
                  <Link
                    href={`/organizations/${orgId}/projects`}
                    className="vf-btn-secondary h-7 px-3 text-[11px]"
                  >
                    Step 1: Projects →
                  </Link>
                )}
                {profiles.length === 0 && (
                  <Link
                    href={`/organizations/${orgId}/scan-profiles`}
                    className="vf-btn-secondary h-7 px-3 text-[11px]"
                  >
                    Scan Profiles →
                  </Link>
                )}
                {authorizations.length === 0 && (
                  <Link
                    href={`/organizations/${orgId}/authorizations`}
                    className="vf-btn-secondary h-7 px-3 text-[11px]"
                  >
                    Step 3: Approvals →
                  </Link>
                )}
              </div>
            </div>
          )}
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            <label className="block text-xs text-zinc-300">
              Project
              <Select
                value={projectId}
                onChange={(e) => setProjectId(e.target.value)}
                required
                className="mt-1"
              >
                <option value="">Select project...</option>
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </Select>
            </label>
            <label className="block text-xs text-zinc-300">
              Environment
              <Select
                value={environmentId}
                onChange={(e) => setEnvironmentId(e.target.value)}
                required
                className="mt-1"
              >
                <option value="">Select environment...</option>
                {environments.map((env) => (
                  <option key={env.id} value={env.id}>
                    {env.name} ({env.environment_type})
                  </option>
                ))}
              </Select>
            </label>
            <label className="block text-xs text-zinc-300">
              Scan Profile
              <Select
                value={scanProfileId}
                onChange={(e) => setScanProfileId(e.target.value)}
                required
                className="mt-1"
              >
                <option value="">Select scan profile...</option>
                {profiles.map((prof) => (
                  <option key={prof.id} value={prof.id}>
                    {prof.name} v{prof.version} ({prof.status})
                  </option>
                ))}
              </Select>
            </label>
            <label className="block text-xs text-zinc-300">
              Approved Authorization
              <Select
                value={authorizationId}
                onChange={(e) => {
                  const nextAuthId = e.target.value;
                  setAuthorizationId(nextAuthId);
                  const matching = snapshots.find(
                    (s) => s.authorization_id === nextAuthId,
                  );
                  setSnapshotId(matching ? matching.id : "");
                }}
                required
                className="mt-1"
              >
                <option value="">Select authorization...</option>
                {authorizations.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.authorization_reference} ({a.permitted_intensity})
                  </option>
                ))}
              </Select>
            </label>
            <label className="block text-xs text-zinc-300">
              Signed Scope Snapshot
              <Select
                value={resolvedSnapshotId}
                onChange={(e) => setSnapshotId(e.target.value)}
                required
                className="mt-1"
              >
                <option value="">Select snapshot...</option>
                {matchingSnapshots.map((s) => (
                  <option key={s.id} value={s.id}>
                    v{s.snapshot_version} — {s.canonical_locator}
                  </option>
                ))}
              </Select>
            </label>
            <label className="block text-xs text-zinc-300">
              Execution Mode
              <Select
                value={executionMode}
                onChange={(e) =>
                  setExecutionMode(e.target.value as "simulated" | "runner")
                }
                className="mt-1"
              >
                <option value="simulated">simulated (Control-plane dummy job)</option>
                <option value="runner">runner (Isolated mTLS container)</option>
              </Select>
            </label>
            {executionMode === "runner" && (
              <label className="block text-xs text-zinc-300">
                Target Runner Pool
                <Select
                  value={targetPoolId}
                  onChange={(e) => setTargetPoolId(e.target.value)}
                  className="mt-1"
                >
                  <option value="">Any active pool in organization</option>
                  {runnerPools.map((pool) => (
                    <option key={pool.id} value={pool.id}>
                      {pool.name} ({pool.pool_type})
                    </option>
                  ))}
                </Select>
              </label>
            )}
            <label className="flex items-center gap-2 pt-6 text-xs text-zinc-300">
              <input
                type="checkbox"
                checked={revalidateDns}
                onChange={(e) => setRevalidateDns(e.target.checked)}
                className="rounded border-white/[0.1] bg-[#0e0e11]"
              />
              Revalidate DNS pinning pre-dispatch
            </label>
          </div>
          <div className="flex justify-end">
            <button
              type="submit"
              disabled={submitting || !resolvedSnapshotId || !authorizationId || !scanProfileId}
              className="vf-btn-primary h-8 px-4 text-xs"
            >
              {submitting ? "Enqueuing..." : "Enqueue Scan Run"}
            </button>
          </div>
        </form>
      )}

      <section className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-5">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold text-white">Scan Runs</h2>
          <span className="text-xs text-zinc-400">{scans.length} loaded</span>
        </div>
        {loading ? (
          <p className="mt-3 text-sm text-zinc-400">Loading scan runs...</p>
        ) : scans.length === 0 ? (
          <p className="mt-3 text-sm text-zinc-400">
            No scan runs recorded for this organization yet.
          </p>
        ) : (
          <div className="mt-4 overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <thead className="border-b border-white/[0.068] text-xs uppercase text-zinc-400">
                <tr>
                  <th className="py-2 pr-4">Run ID</th>
                  <th className="py-2 pr-4">Status</th>
                  <th className="py-2 pr-4">Coverage</th>
                  <th className="py-2 pr-4">Pool</th>
                  <th className="py-2 pr-4">Created</th>
                  <th className="py-2 pr-4">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.06]/80 text-zinc-200">
                {scans.map((scan) => (
                  <tr key={scan.id}>
                    <td className="py-2.5 pr-4 font-mono text-xs">
                      <Link
                        href={`/organizations/${orgId}/scans/${scan.id}`}
                        className="text-zinc-200 hover:underline"
                      >
                        {scan.id.slice(0, 8)}
                      </Link>
                    </td>
                    <td className="py-2.5 pr-4">
                      <span className="rounded bg-[#1c1c20] px-2 py-0.5 text-xs">
                        {scan.status}
                      </span>
                    </td>
                    <td className="py-2.5 pr-4 text-xs text-zinc-300">
                      {scan.coverage_status}
                    </td>
                    <td className="py-2.5 pr-4 text-xs text-zinc-400">
                      {scan.runner_pool}
                    </td>
                    <td className="py-2.5 pr-4 text-xs text-zinc-400">
                      {formatUtc(scan.created_at)}
                    </td>
                    <td className="py-2.5 pr-4 flex gap-2">
                      <Link
                        href={`/organizations/${orgId}/scans/${scan.id}`}
                        className="vf-btn-secondary h-7 px-3 text-xs"
                      >
                        Inspect
                      </Link>
                      {canCancelScan && !TERMINAL_RUN_STATUSES.has(scan.status) && (
                        <button
                          type="button"
                          onClick={() => void handleCancel(scan.id)}
                          className="vf-btn-danger px-2.5 py-1 text-xs"
                        >
                          Cancel
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-5">
        <h2 className="text-base font-semibold text-white">Target Leases</h2>
        {leases.length === 0 ? (
          <p className="mt-2 text-sm text-zinc-400">No target leases recorded.</p>
        ) : (
          <div className="mt-3 overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <thead className="border-b border-white/[0.068] text-xs uppercase text-zinc-400">
                <tr>
                  <th className="py-2 pr-4">Target</th>
                  <th className="py-2 pr-4">Risk Class</th>
                  <th className="py-2 pr-4">Status</th>
                  <th className="py-2 pr-4">Owner</th>
                  <th className="py-2 pr-4">Expires</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.06]/80 text-xs text-zinc-300">
                {leases.map((lease) => (
                  <tr key={lease.id}>
                    <td className="py-2 pr-4 font-mono">{lease.target_locator}</td>
                    <td className="py-2 pr-4">{lease.lease_risk_class}</td>
                    <td className="py-2 pr-4">{lease.status}</td>
                    <td className="py-2 pr-4 font-mono">{lease.lease_owner}</td>
                    <td className="py-2 pr-4">{formatUtc(lease.expires_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

export default function ScansPage() {
  const params = useParams<{ orgId: string }>();
  const orgId = params.orgId;

  return (
    <OrgShell orgId={orgId}>
      {({ auth, membership }) => {
        if (!hasPermission(membership, "scan:read")) {
          return (
            <div className="rounded-lg border border-white/[0.08] bg-[#131317] p-6 text-sm text-zinc-200">
              Your role does not have permission to view scan runs in this
              organization.
            </div>
          );
        }
        return (
          <ScansConsoleContent
            orgId={orgId}
            canStartScan={hasPermission(membership, "scan:start")}
            canCancelScan={hasPermission(membership, "scan:cancel")}
            csrfToken={auth.csrf_token}
          />
        );
      }}
    </OrgShell>
  );
}
