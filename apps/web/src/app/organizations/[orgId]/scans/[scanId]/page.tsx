"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import OrgShell, { hasPermission } from "@/components/OrgShell";
import { apiFetch, formatUtc } from "@/lib/api";
import type { RunnerArtifact, ScanRunDetail, TargetHealthProbe } from "@/lib/types";

const TERMINAL_RUN_STATUSES = new Set([
  "completed",
  "completed_with_errors",
  "partial",
  "failed",
  "rejected",
  "cancelled",
]);

function ScanDetailContent({
  orgId,
  scanId,
  canCancel,
  csrfToken,
}: {
  orgId: string;
  scanId: string;
  canCancel: boolean;
  csrfToken: string | null;
}) {
  const [scan, setScan] = useState<ScanRunDetail | null>(null);
  const [artifacts, setArtifacts] = useState<RunnerArtifact[]>([]);
  const [healthProbes, setHealthProbes] = useState<TargetHealthProbe[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadScan = useCallback(async () => {
    try {
      const [detail, artifactList, probeList] = await Promise.all([
        apiFetch<ScanRunDetail>(`/api/v1/organizations/${orgId}/scans/${scanId}`),
        apiFetch<RunnerArtifact[]>(
          `/api/v1/organizations/${orgId}/scans/${scanId}/artifacts`,
        ).catch(() => [] as RunnerArtifact[]),
        apiFetch<TargetHealthProbe[]>(
          `/api/v1/organizations/${orgId}/scans/${scanId}/health-probes`,
        ).catch(() => [] as TargetHealthProbe[]),
      ]);
      setScan(detail);
      setArtifacts(artifactList);
      setHealthProbes(probeList);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load scan run");
    } finally {
      setLoading(false);
    }
  }, [orgId, scanId]);

  useEffect(() => {
    let active = true;
    void Promise.all([
      apiFetch<ScanRunDetail>(`/api/v1/organizations/${orgId}/scans/${scanId}`),
      apiFetch<RunnerArtifact[]>(
        `/api/v1/organizations/${orgId}/scans/${scanId}/artifacts`,
      ).catch(() => [] as RunnerArtifact[]),
      apiFetch<TargetHealthProbe[]>(
        `/api/v1/organizations/${orgId}/scans/${scanId}/health-probes`,
      ).catch(() => [] as TargetHealthProbe[]),
    ])
      .then(([detail, artifactList, probeList]) => {
        if (!active) return;
        setScan(detail);
        setArtifacts(artifactList);
        setHealthProbes(probeList);
        setError(null);
        setLoading(false);
      })
      .catch((err) => {
        if (!active) return;
        setError(err instanceof Error ? err.message : "Failed to load scan run");
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [orgId, scanId]);

  const handleDownloadArtifact = async (artifact: RunnerArtifact) => {
    try {
      const base =
        process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/$/, "") || "http://127.0.0.1:8000";
      const resp = await fetch(
        `${base}/api/v1/organizations/${orgId}/scans/${scanId}/artifacts/${artifact.id}/download`,
        { credentials: "include" },
      );
      if (!resp.ok) {
        throw new Error(`Download failed (HTTP ${resp.status})`);
      }
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `${artifact.artifact_type}-${artifact.id.slice(0, 8)}`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Artifact download failed");
    }
  };

  const handleCancel = async () => {
    if (!scan) return;
    try {
      const updated = await apiFetch<ScanRunDetail>(
        `/api/v1/organizations/${orgId}/scans/${scan.id}/cancel`,
        {
          method: "POST",
          csrfToken,
          body: JSON.stringify({ reason: "Cancelled from scan detail view" }),
        },
      );
      setScan(updated);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Cancel request failed");
    }
  };

  if (loading) {
    return <p className="text-sm text-zinc-300">Loading orchestration run...</p>;
  }

  if (error || !scan) {
    return (
      <div className="space-y-4">
        <div className="rounded-lg border border-white/[0.08] bg-[#131317] p-4 text-sm text-zinc-200">
          {error || "Scan run not found."}
        </div>
        <Link
          href={`/organizations/${orgId}/scans`}
          className="inline-block vf-btn-secondary px-3 py-1.5 text-xs"
        >
          Back to Scans
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <Link
            href={`/organizations/${orgId}/scans`}
            className="text-xs text-zinc-200 hover:underline"
          >
            &larr; Back to Scan Runs
          </Link>
          <h1 className="mt-1 text-xl font-semibold text-white">
            Scan Run {scan.id.slice(0, 8)}
          </h1>
          <p className="text-xs text-zinc-400">
            Status: <span className="text-zinc-200">{scan.status}</span> | Coverage:{" "}
            <span className="text-zinc-200">{scan.coverage_status}</span> | Policy:{" "}
            <span className="font-mono">{scan.policy_version}</span>
            {scan.source_snapshot_id && (
              <>
                {" "}
                | Source Snapshot:{" "}
                <span className="font-mono text-zinc-200">
                  {scan.source_snapshot_id.slice(0, 8)}
                </span>
              </>
            )}
          </p>
        </div>
        <div className="flex gap-2">
          <Link
            href={`/organizations/${orgId}/findings?scan_run_id=${scan.id}`}
            className="vf-btn-secondary h-8 px-3.5 text-xs"
          >
            View Findings
          </Link>
          <button
            type="button"
            onClick={() => void loadScan()}
            className="vf-btn-secondary h-8 px-3.5 text-xs"
          >
            Refresh
          </button>
          {canCancel && !TERMINAL_RUN_STATUSES.has(scan.status) && (
            <button
              type="button"
              onClick={() => void handleCancel()}
              className="vf-btn-danger h-8 px-3.5 text-xs"
            >
              Cancel Run
            </button>
          )}
        </div>
      </div>

      {healthProbes.some((p) => p.probe_type === "tripwire" || !p.healthy) && (
        <div className="rounded-lg border border-white/[0.08] bg-[#131317] p-4 text-xs text-zinc-200">
          <div className="font-semibold text-zinc-100 flex items-center gap-2">
            <span className="inline-block h-2.5 w-2.5 rounded-full bg-rose-500 animate-pulse" />
            DAST Target Health Safety Tripwire Tripped — Emergency Auto-Abort
          </div>
          <p className="mt-1 text-zinc-200/90">
            {healthProbes.find((p) => p.probe_type === "tripwire" || !p.healthy)?.error_message ||
              "Target safety thresholds breached during active scanning. Execution was safely halted and target lease released."}
          </p>
        </div>
      )}

      {scan.coverage_summary && (
        <section className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-5 text-xs">
          <h2 className="text-sm font-semibold text-white">Source Language Coverage</h2>
          <p className="mt-1 text-zinc-300">
            Assessment:{" "}
            <span className="font-mono text-zinc-200">
              {String(scan.coverage_summary.assessment_coverage_status || scan.coverage_status)}
            </span>{" "}
            | Files Analyzed: {String(scan.coverage_summary.files_total_eligible ?? 0)}
            {scan.source_snapshot_hash && (
              <>
                {" "}
                | Archive SHA-256:{" "}
                <span className="font-mono text-zinc-400">
                  {scan.source_snapshot_hash.slice(0, 16)}...
                </span>
              </>
            )}
          </p>
          <p className="mt-1 text-zinc-400">
            Supported:{" "}
            {Array.isArray(scan.coverage_summary.supported_languages) &&
            scan.coverage_summary.supported_languages.length > 0
              ? scan.coverage_summary.supported_languages.join(", ")
              : "none"}{" "}
            | Unsupported:{" "}
            {Array.isArray(scan.coverage_summary.unsupported_languages) &&
            scan.coverage_summary.unsupported_languages.length > 0
              ? scan.coverage_summary.unsupported_languages.join(", ")
              : "none"}
          </p>
        </section>
      )}

      <section className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-5">
        <h2 className="text-sm font-semibold text-white">Ordered Stages</h2>
        <div className="mt-3 space-y-2">
          {scan.stages.map((stage) => (
            <div
              key={stage.id}
              className="flex flex-wrap items-center justify-between gap-3 rounded border border-white/[0.068] bg-[#0e0e11] px-4 py-2.5 text-xs"
            >
              <div>
                <span className="font-mono text-zinc-200">
                  #{stage.stage_order} {stage.stage_key}
                </span>
                <span className="ml-2 text-zinc-400">({stage.stage_kind})</span>
                {stage.depends_on_stage_key && (
                  <span className="ml-2 text-zinc-500">
                    depends on {stage.depends_on_stage_key}
                  </span>
                )}
              </div>
              <div className="flex items-center gap-3">
                {stage.requires_target_lease && (
                  <span className="rounded bg-[#19191f] px-2 py-0.5 text-zinc-200 border border-white/[0.08]">
                    lease:{stage.lease_risk_class}
                  </span>
                )}
                <span className="rounded bg-[#1c1c20] px-2 py-0.5 text-zinc-200">
                  {stage.status}
                </span>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-5">
        <h2 className="text-sm font-semibold text-white">Orchestration Jobs</h2>
        <div className="mt-3 overflow-x-auto">
          <table className="min-w-full text-left text-xs">
            <thead className="border-b border-white/[0.068] uppercase text-zinc-400">
              <tr>
                <th className="py-2 pr-4">Tool / Dummy Task</th>
                <th className="py-2 pr-4">Status</th>
                <th className="py-2 pr-4">Attempts</th>
                <th className="py-2 pr-4">Executions</th>
                <th className="py-2 pr-4">Completed</th>
                <th className="py-2 pr-4">Last Error</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06] text-zinc-300">
              {scan.jobs.map((job) => (
                <tr key={job.id}>
                  <td className="py-2 pr-4 font-mono">{job.tool_id}</td>
                  <td className="py-2 pr-4">{job.status}</td>
                  <td className="py-2 pr-4">
                    {job.attempt_count}/{job.max_attempts}
                  </td>
                  <td className="py-2 pr-4">{job.execution_count}</td>
                  <td className="py-2 pr-4">{formatUtc(job.completed_at)}</td>
                  <td className="py-2 pr-4 text-rose-300">
                    {job.last_error_code || "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-5">
        <h2 className="text-sm font-semibold text-white">Target Leases</h2>
        {scan.leases.length === 0 ? (
          <p className="mt-2 text-xs text-zinc-400">No target leases required or created.</p>
        ) : (
          <div className="mt-2 space-y-1 text-xs text-zinc-300">
            {scan.leases.map((lease) => (
              <div key={lease.id} className="font-mono">
                {lease.target_locator} | {lease.lease_risk_class} | {lease.status} | owner=
                {lease.lease_owner}
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-5">
        <h2 className="text-sm font-semibold text-white">
          Encrypted Execution Artifacts ({artifacts.length})
        </h2>
        {artifacts.length === 0 ? (
          <p className="mt-2 text-xs text-zinc-400">
            No encrypted execution artifacts uploaded for this run yet.
          </p>
        ) : (
          <div className="mt-3 overflow-x-auto">
            <table className="min-w-full text-left text-xs">
              <thead className="border-b border-white/[0.068] uppercase text-zinc-400">
                <tr>
                  <th className="py-2 pr-4">Type</th>
                  <th className="py-2 pr-4">Content-Type</th>
                  <th className="py-2 pr-4">Bytes</th>
                  <th className="py-2 pr-4">SHA-256</th>
                  <th className="py-2 pr-4">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.06] text-zinc-300">
                {artifacts.map((art) => (
                  <tr key={art.id}>
                    <td className="py-2 pr-4 font-mono">{art.artifact_type}</td>
                    <td className="py-2 pr-4">{art.content_type}</td>
                    <td className="py-2 pr-4">{art.size_bytes}</td>
                    <td className="py-2 pr-4 font-mono">{art.sha256.slice(0, 16)}...</td>
                    <td className="py-2 pr-4">
                      <button
                        type="button"
                        onClick={() => void handleDownloadArtifact(art)}
                        className="vf-btn-secondary h-7 px-3 text-xs"
                      >
                        Decrypt & Download
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-5">
        <h2 className="text-sm font-semibold text-white">
          Target Health Safety Probes ({healthProbes.length})
        </h2>
        {healthProbes.length === 0 ? (
          <p className="mt-2 text-xs text-zinc-400">
            No safety health probes recorded for this scan run.
          </p>
        ) : (
          <div className="mt-3 overflow-x-auto">
            <table className="min-w-full text-left text-xs">
              <thead className="border-b border-white/[0.068] uppercase text-zinc-400">
                <tr>
                  <th className="py-2 pr-4">Type</th>
                  <th className="py-2 pr-4">Target URL</th>
                  <th className="py-2 pr-4">Status</th>
                  <th className="py-2 pr-4">Latency</th>
                  <th className="py-2 pr-4">Health</th>
                  <th className="py-2 pr-4">Recorded At</th>
                  <th className="py-2 pr-4">Detail</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.06] text-zinc-300">
                {healthProbes.map((probe) => (
                  <tr key={probe.id} className={!probe.healthy ? "bg-[#19191f]" : ""}>
                    <td className="py-2 pr-4 font-mono font-semibold text-zinc-200">
                      {probe.probe_type}
                    </td>
                    <td className="py-2 pr-4 font-mono">{probe.target_url}</td>
                    <td className="py-2 pr-4">{probe.status_code ?? "ERR"}</td>
                    <td className="py-2 pr-4">{probe.latency_ms}ms</td>
                    <td className="py-2 pr-4">
                      {probe.healthy ? (
                        <span className="rounded bg-[#1a1a1f] px-2 py-0.5 text-zinc-200 border border-white/[0.08]">
                          healthy
                        </span>
                      ) : (
                        <span className="rounded bg-[#19191f] px-2 py-0.5 text-zinc-200 border border-white/[0.08]">
                          unhealthy
                        </span>
                      )}
                    </td>
                    <td className="py-2 pr-4">{formatUtc(probe.created_at)}</td>
                    <td className="py-2 pr-4 text-rose-300">
                      {probe.error_message || "-"}
                    </td>
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

export default function ScanDetailPage() {
  const params = useParams<{ orgId: string; scanId: string }>();

  return (
    <OrgShell orgId={params.orgId}>
      {({ auth, membership }) => {
        if (!hasPermission(membership, "scan:read")) {
          return (
            <div className="rounded-lg border border-white/[0.08] bg-[#131317] p-6 text-sm text-zinc-200">
              Your role does not have permission to view scan runs.
            </div>
          );
        }
        return (
          <ScanDetailContent
            orgId={params.orgId}
            scanId={params.scanId}
            canCancel={hasPermission(membership, "scan:cancel")}
            csrfToken={auth.csrf_token}
          />
        );
      }}
    </OrgShell>
  );
}
