"use client";

import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import OrgShell, { hasPermission } from "@/components/OrgShell";
import { Select } from "@/components/ui/Select";
import { apiFetch } from "@/lib/api";
import type {
  OrganizationMembershipSummary,
  ToolCatalogItem,
  ToolUpdateItem,
  UpdateLifecycleOverview,
} from "@/lib/types";

const STREAM_LABELS: Record<string, string> = {
  engines_and_base_images: "Stream 1 — Scanner Engines, Base Images & Crypto",
  rules_templates_addons: "Stream 2 — Rules, Templates & Add-ons",
  vulnerability_intel_dbs: "Stream 3 — Vulnerability DBs & Threat Feeds",
  adapters_and_dependencies: "Stream 4 — Adapters, AI & App Dependencies",
};

function UpdatesLifecycleContent({
  orgId,
  membership,
  csrfToken,
}: {
  orgId: string;
  membership: OrganizationMembershipSummary | null;
  csrfToken: string;
}) {
  const canManage = hasPermission(membership, "update:manage");
  const [overview, setOverview] = useState<UpdateLifecycleOverview | null>(null);
  const [selectedStream, setSelectedStream] = useState<string>("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionMsg, setActionMsg] = useState<string | null>(null);

  // Register Candidate modal/form state
  const [toolSlug, setToolSlug] = useState("opengrep");
  const [versionTag, setVersionTag] = useState("1.34.0");
  const [imageRepo, setImageRepo] = useState("vforge-opengrep:1.34.0");
  const [imageDigest, setImageDigest] = useState(
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  );
  const [changeType, setChangeType] = useState("minor");
  const [isEmergency, setIsEmergency] = useState(false);
  const [emergencyJustification, setEmergencyJustification] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const loadOverview = useCallback(async () => {
    try {
      const data = await apiFetch<UpdateLifecycleOverview>(
        `/api/v1/organizations/${orgId}/updates/overview`,
      );
      setOverview(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load update lifecycle overview");
    } finally {
      setLoading(false);
    }
  }, [orgId]);

  useEffect(() => {
    let active = true;
    void apiFetch<UpdateLifecycleOverview>(`/api/v1/organizations/${orgId}/updates/overview`)
      .then((data) => {
        if (!active) return;
        setOverview(data);
        setError(null);
        setLoading(false);
      })
      .catch((err) => {
        if (!active) return;
        setError(err instanceof Error ? err.message : "Failed to load update lifecycle overview");
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [orgId]);

  const handleDetectLocks = async () => {
    setSubmitting(true);
    setActionMsg(null);
    try {
      const res = await apiFetch<{ detected_count: number }>(`/api/v1/updates/detect`, {
        method: "POST",
        csrfToken,
      });
      setActionMsg(`Image-lock scan complete: detected ${res.detected_count} new candidates.`);
      await loadOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Lock manifest check failed");
    } finally {
      setSubmitting(false);
    }
  };

  const handleRegisterCandidate = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setActionMsg(null);
    try {
      const res = await apiFetch<ToolUpdateItem>(`/api/v1/updates/candidates`, {
        method: "POST",
        csrfToken,
        body: JSON.stringify({
          tool_slug: toolSlug,
          version_tag: versionTag,
          image_repository: imageRepo,
          image_digest: imageDigest,
          change_type: changeType,
          is_emergency: isEmergency,
          emergency_justification: isEmergency ? emergencyJustification : null,
        }),
      });
      setActionMsg(
        `Registered candidate ${res.tool_slug} ${res.version_tag} (${res.status}). Run validation gates next.`,
      );
      await loadOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to register candidate");
    } finally {
      setSubmitting(false);
    }
  };

  const handleValidate = async (updateId: string, simulateFail = false) => {
    setSubmitting(true);
    setActionMsg(null);
    try {
      const res = await apiFetch<ToolUpdateItem>(`/api/v1/updates/${updateId}/validate`, {
        method: "POST",
        csrfToken,
        body: JSON.stringify({
          automated: true,
          simulate_failure_gate: simulateFail ? "regression_corpus" : null,
        }),
      });
      setActionMsg(`Validation gates executed for ${res.tool_slug}: status -> ${res.status}`);
      await loadOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Validation run failed");
    } finally {
      setSubmitting(false);
    }
  };

  const handleApprove = async (update: ToolUpdateItem, emergency = false) => {
    setSubmitting(true);
    setActionMsg(null);
    try {
      const justification = emergency
        ? "Emergency security advisory remediation approved with intact contract and provenance gates."
        : null;
      const res = await apiFetch<ToolUpdateItem>(`/api/v1/updates/${update.id}/approve`, {
        method: "POST",
        csrfToken,
        body: JSON.stringify({
          is_emergency: emergency,
          emergency_justification: justification,
        }),
      });
      setActionMsg(`Approved ${res.tool_slug} ${res.version_tag}.`);
      await loadOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Approval failed");
    } finally {
      setSubmitting(false);
    }
  };

  const handlePromote = async (updateId: string, channel: "canary" | "stable") => {
    setSubmitting(true);
    setActionMsg(null);
    try {
      const res = await apiFetch<ToolUpdateItem>(`/api/v1/updates/${updateId}/promote`, {
        method: "POST",
        csrfToken,
        body: JSON.stringify({ target_channel: channel }),
      });
      setActionMsg(`Promoted ${res.tool_slug} ${res.version_tag} to ${channel}.`);
      await loadOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : `Promotion to ${channel} failed`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleRollbackTool = async (
    tool: ToolCatalogItem,
    channel: "canary" | "stable" = "stable",
  ) => {
    setSubmitting(true);
    setActionMsg(null);
    try {
      const res = await apiFetch<{
        demoted_version: { version_tag: string };
        restored_version?: { version_tag: string } | null;
      }>(`/api/v1/updates/tools/${tool.tool_slug}/rollback`, {
        method: "POST",
        csrfToken,
        body: JSON.stringify({
          reason: `Operator-triggered ${channel} zero-rebuild rollback from Updates console`,
          channel,
        }),
      });
      setActionMsg(
        `Rolled back ${tool.tool_slug} ${channel} (${res.demoted_version.version_tag})` +
          (res.restored_version ? ` -> restored ${res.restored_version.version_tag}` : ""),
      );
      await loadOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : `Rollback failed for ${tool.tool_slug}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleFeedPromote = async (snapshotId: string, channel: "canary" | "stable") => {
    setSubmitting(true);
    setActionMsg(null);
    try {
      const res = await apiFetch<{ feed_slug: string; snapshot_tag: string }>(
        `/api/v1/updates/feeds/${snapshotId}/promote`,
        {
          method: "POST",
          csrfToken,
          body: JSON.stringify({ target_channel: channel }),
        },
      );
      setActionMsg(`Promoted feed ${res.feed_slug} (${res.snapshot_tag}) to ${channel}.`);
      await loadOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Feed promotion failed");
    } finally {
      setSubmitting(false);
    }
  };

  const handleFeedRollback = async (feedSlug: string) => {
    setSubmitting(true);
    setActionMsg(null);
    try {
      const res = await apiFetch<{ feed_slug: string; snapshot_tag: string }>(
        `/api/v1/updates/feeds/${feedSlug}/rollback`,
        {
          method: "POST",
          csrfToken,
          body: JSON.stringify({
            reason: "Operator-triggered feed snapshot rollback from Updates console",
          }),
        },
      );
      setActionMsg(`Rolled back feed ${res.feed_slug} -> restored ${res.snapshot_tag}.`);
      await loadOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Feed rollback failed");
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return <p className="text-sm text-zinc-300">Loading release &amp; update lifecycle registry...</p>;
  }

  const tools = (overview?.tools || []).filter(
    (t) => selectedStream === "all" || t.stream === selectedStream,
  );
  const updates = (overview?.updates || []).filter(
    (u) => selectedStream === "all" || u.stream === selectedStream,
  );

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-white">
            Release &amp; Update Lifecycle Console
          </h1>
          <p className="mt-1 text-sm text-zinc-400">
            Four independent streams, digest-only image pinning, mandatory validation gates,
            canary/stable promotion, and instant zero-rebuild rollback.
          </p>
        </div>
        {canManage && (
          <button
            type="button"
            disabled={submitting}
            onClick={handleDetectLocks}
            className="vf-btn-primary h-8 px-4 text-xs"
          >
            Scan Image-Lock Manifests
          </button>
        )}
      </div>

      {error && (
        <div className="rounded-lg border border-white/[0.08] bg-[#131317] p-4 text-sm text-zinc-200">
          {error}
        </div>
      )}
      {actionMsg && (
        <div className="rounded-lg border border-white/[0.08] bg-[#121614] p-4 text-sm text-zinc-200">
          {actionMsg}
        </div>
      )}

      {/* Stream Filter Tabs */}
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => setSelectedStream("all")}
          className={`rounded-full px-3.5 py-1.5 text-xs font-medium border transition ${
            selectedStream === "all"
              ? "border-white/[0.15] bg-[#1e1e24] text-white"
              : "border-white/[0.07] bg-[#141418] text-zinc-400 hover:bg-white/[0.04] hover:text-zinc-200"
          }`}
        >
          All 4 Streams ({overview?.tools.length || 0})
        </button>
        {(overview?.streams || []).map((stream) => (
          <button
            key={stream}
            type="button"
            onClick={() => setSelectedStream(stream)}
            className={`rounded-full px-3.5 py-1.5 text-xs font-medium border transition ${
              selectedStream === stream
                ? "border-white/[0.15] bg-[#1e1e24] text-white"
                : "border-white/[0.07] bg-[#141418] text-zinc-400 hover:bg-white/[0.04] hover:text-zinc-200"
            }`}
          >
            {STREAM_LABELS[stream] || stream}
          </button>
        ))}
      </div>

      {/* Active Pinned Tool Catalog */}
      <section className="rounded-xl border border-white/[0.068] bg-[#141417] p-6">
        <h2 className="text-lg font-semibold text-white">Digest-Pinned Tool &amp; Component Catalog</h2>
        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-left text-xs text-zinc-300">
            <thead className="border-b border-white/[0.068] text-zinc-400">
              <tr>
                <th className="py-2 pr-4">Tool</th>
                <th className="py-2 pr-4">Stream / Channel</th>
                <th className="py-2 pr-4">Automerge</th>
                <th className="py-2 pr-4">Active Stable Pin</th>
                <th className="py-2 pr-4">Active Canary</th>
                <th className="py-2">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06]">
              {tools.map((tool) => (
                <tr key={tool.id}>
                  <td className="py-3 pr-4">
                    <div className="font-medium text-white">{tool.display_name}</div>
                    <div className="text-zinc-400">{tool.tool_slug}</div>
                  </td>
                  <td className="py-3 pr-4">
                    <div className="text-zinc-200">{tool.stream}</div>
                    <div className="text-zinc-400">{tool.update_channel}</div>
                  </td>
                  <td className="py-3 pr-4">
                    {tool.automerge_allowed ? (
                      <span className="rounded bg-[#19191f] px-2 py-0.5 text-amber-300">
                        gated
                      </span>
                    ) : (
                      <span className="rounded bg-[#1c1c20] px-2 py-0.5 text-zinc-300">
                        disabled
                      </span>
                    )}
                  </td>
                  <td className="py-3 pr-4 font-mono">
                    {tool.active_stable_version ? (
                      <div>
                        <div className="text-zinc-200">{tool.active_stable_version.version_tag}</div>
                        <div className="text-[11px] text-zinc-400">
                          {tool.active_stable_version.image_digest.slice(0, 22)}...
                        </div>
                      </div>
                    ) : (
                      <span className="text-zinc-500">none</span>
                    )}
                  </td>
                  <td className="py-3 pr-4 font-mono">
                    {tool.active_canary_version ? (
                      <div>
                        <div className="text-[#93c5fd]">{tool.active_canary_version.version_tag}</div>
                        <div className="text-[11px] text-zinc-400">
                          {tool.active_canary_version.image_digest.slice(0, 22)}...
                        </div>
                      </div>
                    ) : (
                      <span className="text-zinc-500">-</span>
                    )}
                  </td>
                  <td className="py-3">
                    {canManage && (
                      <div className="flex flex-wrap gap-1.5">
                        {tool.active_canary_version && (
                          <button
                            type="button"
                            disabled={submitting}
                            onClick={() => void handleRollbackTool(tool, "canary")}
                            className="vf-btn-warning h-7 px-3 text-xs"
                          >
                            Rollback Canary
                          </button>
                        )}
                        {tool.active_stable_version && (
                          <button
                            type="button"
                            disabled={submitting}
                            onClick={() => void handleRollbackTool(tool, "stable")}
                            className="vf-btn-danger h-7 px-3 text-xs"
                          >
                            Rollback Stable
                          </button>
                        )}
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Register Candidate Update Form */}
      {canManage && (
        <section className="rounded-xl border border-white/[0.068] bg-[#141417] p-6">
          <h2 className="text-lg font-semibold text-white">Register Digest-Pinned Update Candidate</h2>
          <form onSubmit={handleRegisterCandidate} className="mt-4 grid gap-4 md:grid-cols-3">
            <div>
              <label className="block text-xs text-zinc-400">Tool Slug</label>
              <Select
                value={toolSlug}
                onChange={(e) => setToolSlug(e.target.value)}
                className="mt-1"
              >
                {(overview?.tools || []).map((t) => (
                  <option key={t.id} value={t.tool_slug}>
                    {t.tool_slug} ({t.stream})
                  </option>
                ))}
              </Select>
            </div>
            <div>
              <label className="block text-xs text-zinc-400">Version Tag (never :latest)</label>
              <input
                value={versionTag}
                onChange={(e) => setVersionTag(e.target.value)}
                className="mt-1 vf-input"
                required
              />
            </div>
            <div>
              <label className="block text-xs text-zinc-400">Change Type</label>
              <Select
                value={changeType}
                onChange={(e) => setChangeType(e.target.value)}
                className="mt-1"
              >
                <option value="patch">patch</option>
                <option value="minor">minor</option>
                <option value="major">major</option>
                <option value="security">security</option>
                <option value="feed_refresh">feed_refresh</option>
              </Select>
            </div>
            <div>
              <label className="block text-xs text-zinc-400">Image Repository</label>
              <input
                value={imageRepo}
                onChange={(e) => setImageRepo(e.target.value)}
                className="mt-1 vf-input"
                required
              />
            </div>
            <div className="md:col-span-2">
              <label className="block text-xs text-zinc-400">SHA-256 Digest (sha256:64-hex)</label>
              <input
                value={imageDigest}
                onChange={(e) => setImageDigest(e.target.value)}
                className="mt-1 w-full rounded border border-white/[0.1] bg-[#0e0e11] px-3 py-2 font-mono text-sm text-white"
                required
              />
            </div>
            <div className="flex items-center gap-2 md:col-span-3">
              <input
                id="is_emergency"
                type="checkbox"
                checked={isEmergency}
                onChange={(e) => setIsEmergency(e.target.checked)}
                className="h-4 w-4 rounded border-white/[0.1] bg-[#0e0e11]"
              />
              <label htmlFor="is_emergency" className="text-xs text-amber-300">
                Mark as Emergency Security Update (requires justification)
              </label>
            </div>
            {isEmergency && (
              <div className="md:col-span-3">
                <label className="block text-xs text-zinc-400">Emergency Security Justification</label>
                <input
                  value={emergencyJustification}
                  onChange={(e) => setEmergencyJustification(e.target.value)}
                  placeholder="CVE / zero-day advisory reference and rollback validation"
                  className="mt-1 vf-input"
                  required
                />
              </div>
            )}
            <div className="md:col-span-3">
              <button
                type="submit"
                disabled={submitting}
                className="vf-btn-primary h-8 px-4 text-xs"
              >
                Register Candidate Release
              </button>
            </div>
          </form>
        </section>
      )}

      {/* Candidate Updates & Gate Pipeline */}
      <section className="rounded-xl border border-white/[0.068] bg-[#141417] p-6">
        <h2 className="text-lg font-semibold text-white">Update Promotion Pipeline &amp; Gate Evidence</h2>
        <div className="mt-4 space-y-4">
          {updates.length === 0 && (
            <p className="text-sm text-zinc-400">No update candidates registered yet.</p>
          )}
          {updates.map((upd) => (
            <div key={upd.id} className="rounded-lg border border-white/[0.068] bg-[#0e0e11] p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <span className="font-semibold text-white">
                    {upd.tool_slug} &rarr; {upd.version_tag}
                  </span>
                  <span className="ml-3 rounded bg-[#1c1c20] px-2 py-0.5 text-xs text-zinc-300">
                    {upd.status}
                  </span>
                  {upd.is_emergency && (
                    <span className="ml-2 rounded bg-[#19191f] px-2 py-0.5 text-xs text-amber-300">
                      EMERGENCY
                    </span>
                  )}
                </div>
                {canManage && (
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      disabled={submitting}
                      onClick={() => void handleValidate(upd.id, false)}
                      className="vf-btn-secondary h-7 px-3 text-xs"
                    >
                      Run Verification Gates
                    </button>
                    <button
                      type="button"
                      disabled={submitting}
                      onClick={() => void handleApprove(upd, upd.is_emergency)}
                      className="vf-btn-primary h-7 px-3 text-xs"
                    >
                      Approve
                    </button>
                    <button
                      type="button"
                      disabled={submitting}
                      onClick={() => void handlePromote(upd.id, "canary")}
                      className="vf-btn-secondary h-7 px-3 text-xs"
                    >
                      Promote Canary
                    </button>
                    <button
                      type="button"
                      disabled={submitting}
                      onClick={() => void handlePromote(upd.id, "stable")}
                      className="vf-btn-secondary h-7 px-3 text-xs"
                    >
                      Promote Stable
                    </button>
                  </div>
                )}
              </div>
              <p className="mt-1 font-mono text-xs text-zinc-400">
                Digest: {upd.image_digest} | Channel: {upd.update_channel}
              </p>
              {upd.rejection_reason && (
                <p className="mt-1 text-xs text-rose-300">Rejected: {upd.rejection_reason}</p>
              )}
              {upd.rollback_reason && (
                <p className="mt-1 text-xs text-amber-300">Rolled Back: {upd.rollback_reason}</p>
              )}
              {upd.test_results.length > 0 && (
                <div className="mt-3 flex flex-wrap gap-2">
                  {upd.test_results.map((t) => (
                    <span
                      key={t.id}
                      className={`rounded px-2 py-0.5 text-[11px] ${
                        t.outcome === "passed"
                          ? "bg-[#1a1a1f] text-zinc-200"
                          : t.outcome === "failed"
                            ? "bg-[#19191f] text-rose-300"
                            : "bg-[#1c1c20] text-zinc-300"
                      }`}
                    >
                      {t.test_category}: {t.outcome}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </section>

      {/* Feed Snapshots & Audit Log */}
      <div className="grid gap-6 md:grid-cols-2">
        <section className="rounded-xl border border-white/[0.068] bg-[#141417] p-6">
          <h2 className="text-lg font-semibold text-white">Vulnerability DB &amp; Rule Pack Snapshots</h2>
          <div className="mt-3 space-y-2 text-xs text-zinc-300">
            {(overview?.feed_snapshots || []).map((f) => (
              <div key={f.id} className="rounded border border-white/[0.068] bg-[#0e0e11] p-3">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-white">
                    {f.feed_slug} ({f.snapshot_tag})
                  </span>
                  <span className="rounded bg-[#1a1a1f] px-2 py-0.5 text-zinc-200">
                    {f.is_active_stable ? "stable" : f.is_active_canary ? "canary" : f.approval_channel}
                  </span>
                </div>
                <div className="mt-1 font-mono text-[11px] text-zinc-400">
                  SHA-256: {f.archive_sha256.slice(0, 24)}... | Records: {f.record_count}
                </div>
                {canManage && (
                  <div className="mt-2 flex flex-wrap gap-2">
                    {!f.is_active_canary && !f.is_active_stable && (
                      <button
                        type="button"
                        disabled={submitting}
                        onClick={() => void handleFeedPromote(f.id, "canary")}
                        className="vf-btn-secondary h-6 px-2.5 text-[11px]"
                      >
                        Promote Canary
                      </button>
                    )}
                    {!f.is_active_stable && (
                      <button
                        type="button"
                        disabled={submitting}
                        onClick={() => void handleFeedPromote(f.id, "stable")}
                        className="vf-btn-secondary h-6 px-2.5 text-[11px]"
                      >
                        Promote Stable
                      </button>
                    )}
                    {f.is_active_stable && f.previous_stable_snapshot_id && (
                      <button
                        type="button"
                        disabled={submitting}
                        onClick={() => void handleFeedRollback(f.feed_slug)}
                        className="vf-btn-danger h-6 px-2.5 text-[11px]"
                      >
                        Rollback Feed
                      </button>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </section>

        <section className="rounded-xl border border-white/[0.068] bg-[#141417] p-6">
          <h2 className="text-lg font-semibold text-white">Immutable Update Governance Audit Trail</h2>
          <div className="mt-3 max-h-80 space-y-2 overflow-y-auto text-xs text-zinc-300">
            {(overview?.audit_events || []).map((evt) => (
              <div key={evt.id} className="rounded border border-white/[0.068] bg-[#0e0e11] p-3">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-[#93c5fd]">{evt.action}</span>
                  <span className="text-zinc-500">{new Date(evt.occurred_at).toLocaleString()}</span>
                </div>
                {evt.reason && <p className="mt-1 text-zinc-300">{evt.reason}</p>}
                {evt.actor_email && <p className="text-[11px] text-zinc-500">Actor: {evt.actor_email}</p>}
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}

export default function OrganizationUpdatesPage() {
  const params = useParams<{ orgId: string }>();
  const orgId = params.orgId;

  return (
    <OrgShell orgId={orgId}>
      {({ auth, membership }) => (
        <UpdatesLifecycleContent
          orgId={orgId}
          membership={membership}
          csrfToken={auth.csrf_token || ""}
        />
      )}
    </OrgShell>
  );
}
