"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { FormEvent, useCallback, useEffect, useState } from "react";
import OrgShell, { hasPermission } from "@/components/OrgShell";
import { StatusBadge } from "@/components/ui/Badge";
import { Select } from "@/components/ui/Select";
import { apiFetch, formatUtc } from "@/lib/api";
import {
  INTENSITY_LEVELS,
  TESTING_CAPABILITIES,
  type Asset,
  type Authorization,
  type IntensityLevel,
  type PaginatedResponse,
  type ScopeSnapshot,
  type SnapshotVerifyResponse,
} from "@/lib/types";

const STATUS_FILTERS = [
  "all",
  "pending",
  "approved",
  "expired",
  "rejected",
  "revoked",
] as const;

type StatusFilter = (typeof STATUS_FILTERS)[number];

function csvList(value: string): string[] {
  return value
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function asStringArray(value: unknown): string {
  if (!Array.isArray(value)) return "";
  return value.map((item) => String(item)).join(", ");
}

function AuthorizationsContent({
  orgId,
  currentUserId,
  canRequest,
  canApprove,
  canRevoke,
  canVerifySnapshot,
  csrfToken,
}: {
  orgId: string;
  currentUserId: string;
  canRequest: boolean;
  canApprove: boolean;
  canRevoke: boolean;
  canVerifySnapshot: boolean;
  csrfToken: string | null;
}) {
  const [authorizations, setAuthorizations] = useState<Authorization[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [snapshots, setSnapshots] = useState<ScopeSnapshot[]>([]);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [editingId, setEditingId] = useState<string | null>(null);
  const [assetId, setAssetId] = useState("");
  const [reference, setReference] = useState("");
  const [selectedCapabilities, setSelectedCapabilities] = useState<string[]>([
    "passive_web_testing",
    "source_code_analysis",
  ]);
  const [permittedIntensity, setPermittedIntensity] =
    useState<IntensityLevel>("passive");
  const [domainMatchMode, setDomainMatchMode] = useState<
    "exact_domain" | "domain_and_subdomains"
  >("exact_domain");
  const [urlMatchMode, setUrlMatchMode] = useState<
    "exact_url" | "url_path_prefix"
  >("url_path_prefix");
  const [extraDomains, setExtraDomains] = useState("");
  const [extraIps, setExtraIps] = useState("");
  const [extraCidrs, setExtraCidrs] = useState("");
  const [allowedPorts, setAllowedPorts] = useState("443, 8443");
  const [allowPrivateNetworks, setAllowPrivateNetworks] = useState(false);
  const [productionActiveApproved, setProductionActiveApproved] =
    useState(false);
  const [validHours, setValidHours] = useState(168);
  const [submitting, setSubmitting] = useState(false);

  const [expandedHistory, setExpandedHistory] = useState<Record<string, boolean>>({});
  const [verifyResults, setVerifyResults] = useState<
    Record<string, SnapshotVerifyResponse>
  >({});

  const fetchAuthzData = useCallback(
    async (filter: StatusFilter) => {
      const statusQuery = filter === "all" ? "" : `&status=${filter}`;
      const [authRes, assetRes, snapRes] = await Promise.all([
        apiFetch<PaginatedResponse<Authorization>>(
          `/api/v1/organizations/${orgId}/authorizations?limit=100${statusQuery}`,
        ),
        apiFetch<PaginatedResponse<Asset>>(
          `/api/v1/organizations/${orgId}/assets?limit=100`,
        ),
        apiFetch<PaginatedResponse<ScopeSnapshot>>(
          `/api/v1/organizations/${orgId}/snapshots?limit=100`,
        ).catch(() => ({ items: [] as ScopeSnapshot[], total: 0, limit: 100, offset: 0 })),
      ]);
      return { authRes, assetRes, snapRes };
    },
    [orgId],
  );

  const load = useCallback(
    async (filter: StatusFilter = statusFilter) => {
      try {
        const { authRes, assetRes, snapRes } = await fetchAuthzData(filter);
        setAuthorizations(authRes.items);
        setAssets(assetRes.items);
        setSnapshots(snapRes.items);
        if (assetRes.items.length > 0) {
          setAssetId((prev) => prev || assetRes.items[0].id);
        }
        setError(null);
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Failed to load authorizations",
        );
      } finally {
        setLoading(false);
      }
    },
    [fetchAuthzData, statusFilter],
  );

  useEffect(() => {
    let active = true;
    void fetchAuthzData(statusFilter)
      .then(({ authRes, assetRes, snapRes }) => {
        if (!active) return;
        setAuthorizations(authRes.items);
        setAssets(assetRes.items);
        setSnapshots(snapRes.items);
        if (assetRes.items.length > 0) {
          setAssetId((prev) => prev || assetRes.items[0].id);
        }
        setError(null);
        setLoading(false);
      })
      .catch((err) => {
        if (!active) return;
        setError(
          err instanceof Error ? err.message : "Failed to load authorizations",
        );
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [fetchAuthzData, statusFilter]);

  const resetForm = () => {
    setEditingId(null);
    setReference("");
    setSelectedCapabilities(["passive_web_testing", "source_code_analysis"]);
    setPermittedIntensity("passive");
    setDomainMatchMode("exact_domain");
    setUrlMatchMode("url_path_prefix");
    setExtraDomains("");
    setExtraIps("");
    setExtraCidrs("");
    setAllowedPorts("443, 8443");
    setAllowPrivateNetworks(false);
    setProductionActiveApproved(false);
    setValidHours(168);
  };

  const startEdit = (auth: Authorization) => {
    const scope = auth.approved_testing_scope || {};
    setEditingId(auth.id);
    setAssetId(auth.asset_id);
    setReference(auth.authorization_reference);
    setSelectedCapabilities([...auth.approved_activities]);
    setPermittedIntensity(auth.permitted_intensity);
    setDomainMatchMode(
      scope.domain_match_mode === "domain_and_subdomains"
        ? "domain_and_subdomains"
        : "exact_domain",
    );
    setUrlMatchMode(
      scope.url_match_mode === "exact_url" ? "exact_url" : "url_path_prefix",
    );
    setExtraDomains(asStringArray(scope.domains));
    setExtraIps(asStringArray(scope.ips));
    setExtraCidrs(asStringArray(scope.cidrs));
    setAllowedPorts(auth.allowed_ports ? auth.allowed_ports.join(", ") : "");
    setAllowPrivateNetworks(auth.allow_private_networks);
    setProductionActiveApproved(Boolean(scope.production_active_approved));
    setError(null);
    setNotice(
      "Editing authorization. Any change to scope or capabilities resets status to pending for re-approval.",
    );
  };

  const toggleCapability = (cap: string) => {
    setSelectedCapabilities((prev) =>
      prev.includes(cap) ? prev.filter((item) => item !== cap) : [...prev, cap],
    );
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!assetId) {
      setError("Select a registered asset first.");
      return;
    }
    if (selectedCapabilities.length === 0) {
      setError("Select at least one explicit testing capability.");
      return;
    }

    setSubmitting(true);
    setError(null);
    setNotice(null);

    const now = new Date();
    const expires = new Date(now.getTime() + validHours * 3600 * 1000);
    const parsedPorts = csvList(allowedPorts)
      .map((s) => Number.parseInt(s, 10))
      .filter((n) => Number.isInteger(n) && n >= 1 && n <= 65535);

    const testingScope: Record<string, unknown> = {
      domain_match_mode: domainMatchMode,
      url_match_mode: urlMatchMode,
      production_active_approved: productionActiveApproved,
    };
    const domainsList = csvList(extraDomains);
    const ipsList = csvList(extraIps);
    const cidrsList = csvList(extraCidrs);
    if (domainsList.length > 0) testingScope.domains = domainsList;
    if (ipsList.length > 0) testingScope.ips = ipsList;
    if (cidrsList.length > 0) testingScope.cidrs = cidrsList;

    try {
      if (editingId) {
        await apiFetch<Authorization>(
          `/api/v1/organizations/${orgId}/authorizations/${editingId}`,
          {
            method: "PATCH",
            csrfToken,
            body: JSON.stringify({
              approved_testing_scope: testingScope,
              approved_activities: selectedCapabilities,
              allowed_ports: parsedPorts.length > 0 ? parsedPorts : null,
              permitted_intensity: permittedIntensity,
              allow_private_networks: allowPrivateNetworks,
              authorization_reference: reference.trim(),
              valid_from: now.toISOString(),
              expires_at: expires.toISOString(),
            }),
          },
        );
        setNotice(
          "Authorization updated and queued for second-person re-approval.",
        );
        resetForm();
      } else {
        await apiFetch<Authorization>(
          `/api/v1/organizations/${orgId}/authorizations`,
          {
            method: "POST",
            csrfToken,
            body: JSON.stringify({
              asset_id: assetId,
              approved_testing_scope: testingScope,
              approved_activities: selectedCapabilities,
              allowed_ports: parsedPorts.length > 0 ? parsedPorts : null,
              permitted_intensity: permittedIntensity,
              allow_private_networks: allowPrivateNetworks,
              authorization_reference: reference.trim(),
              valid_from: now.toISOString(),
              expires_at: expires.toISOString(),
            }),
          },
        );
        setNotice(
          "Authorization requested. A second Security Lead or Owner must approve it to mint a signed scope snapshot.",
        );
        resetForm();
      }
      await load();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to save authorization",
      );
    } finally {
      setSubmitting(false);
    }
  };

  const handleDecision = async (
    authId: string,
    action: "approve" | "reject" | "revoke",
  ) => {
    setError(null);
    setNotice(null);
    const reason =
      action === "revoke"
        ? "Revoked via control plane governance UI"
        : action === "approve"
          ? "Approved after scope, capability, and DNS safety review"
          : "Rejected by governance reviewer";
    try {
      await apiFetch<Authorization>(
        `/api/v1/organizations/${orgId}/authorizations/${authId}/${action}`,
        {
          method: "POST",
          csrfToken,
          body: JSON.stringify({ reason }),
        },
      );
      setNotice(
        action === "approve"
          ? "Authorization approved and Ed25519 immutable scope snapshot created."
          : `Authorization ${action}d.`,
      );
      await load();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : `Failed to ${action} authorization`,
      );
    }
  };

  const handleVerifySnapshot = async (snapshotId: string) => {
    setError(null);
    try {
      const res = await apiFetch<SnapshotVerifyResponse>(
        `/api/v1/organizations/${orgId}/snapshots/${snapshotId}/verify`,
        {
          method: "POST",
          csrfToken,
          body: JSON.stringify({ revalidate_dns: true }),
        },
      );
      setVerifyResults((prev) => ({ ...prev, [snapshotId]: res }));
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to verify snapshot",
      );
    }
  };

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="mb-1 text-[11px] font-semibold uppercase tracking-[0.12em] text-blue-400">
            Step 3 of 6 · Safety Permission Gate
          </div>
          <h1 className="text-2xl font-semibold text-white">
            Scan Approvals ({authorizations.length})
          </h1>
          <p className="mt-1 text-sm text-zinc-400">
            Before VForge scans anything, confirm ownership and allowed hours here so tests never hit unauthorized systems.
          </p>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {STATUS_FILTERS.map((filter) => (
            <button
              key={filter}
              type="button"
              onClick={() => setStatusFilter(filter)}
              className={`rounded-lg border px-2.5 py-1 text-xs capitalize transition ${
                statusFilter === filter
                  ? "border-blue-500/45 bg-blue-500/15 text-blue-200"
                  : "border-white/[0.068] bg-[#111114] text-zinc-300 hover:bg-white/[0.06]"
              }`}
            >
              {filter}
            </button>
          ))}
        </div>
      </div>

      {error ? (
        <div className="rounded-md border border-white/[0.08] bg-[#131317] p-4 text-sm text-zinc-200">
          {error}
        </div>
      ) : null}
      {notice ? (
        <div className="rounded-md border border-white/[0.08] bg-[#121614] p-4 text-sm text-zinc-200">
          {notice}
        </div>
      ) : null}

      <section className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-6">
        <h2 className="text-lg font-medium text-white">Registered Assets</h2>
        {assets.length === 0 ? (
          <p className="mt-2 text-sm text-amber-300">
            No registered assets found in this organization.
          </p>
        ) : (
          <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {assets.map((asset) => (
              <div
                key={asset.id}
                className="rounded border border-white/[0.068] bg-[#0e0e11]/70 px-3 py-2 text-xs"
              >
                <div className="flex items-center justify-between text-zinc-400">
                  <span>{asset.asset_type}</span>
                  <span>
                    {asset.registration_state} · v{asset.version ?? 1}
                  </span>
                </div>
                <div className="mt-1 truncate font-mono text-zinc-200">
                  {asset.normalized_locator}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-6">
        <h2 className="text-lg font-medium text-white">Authorization Records</h2>
        {loading ? (
          <p className="mt-4 text-sm text-zinc-400">Loading authorizations...</p>
        ) : authorizations.length === 0 ? (
          <p className="mt-4 text-sm text-zinc-400">
            No authorizations match filter &quot;{statusFilter}&quot;.
          </p>
        ) : (
          <div className="mt-4 space-y-4">
            {authorizations.map((a) => {
              const asset = assets.find((item) => item.id === a.asset_id);
              const isSelfRequest = a.requested_by === currentUserId;
              const authSnapshots = snapshots.filter(
                (s) => s.authorization_id === a.id,
              );
              const historyOpen = Boolean(expandedHistory[a.id]);
              return (
                <div
                  key={a.id}
                  className="rounded-2xl border border-white/[0.068] bg-[#101014] p-5 shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]"
                >
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div className="space-y-1.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-medium text-white">
                          {a.authorization_reference}
                        </span>
                        <StatusBadge status={a.status} />
                        <span className="rounded-full border border-white/[0.07] bg-[#16161b] px-2.5 py-0.5 text-[11px] text-zinc-300">
                          intensity: {a.permitted_intensity}
                        </span>
                        <span className="rounded-full border border-white/[0.07] bg-[#16161b] px-2.5 py-0.5 text-[11px] text-zinc-400">
                          policy: {a.policy_version}
                        </span>
                        {a.allow_private_networks ? (
                          <span className="inline-flex items-center gap-1.5 rounded-full border border-white/[0.07] bg-[#16161b] px-2.5 py-0.5 text-[11px] text-zinc-300">
                            <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
                            private networks allowed
                          </span>
                        ) : null}
                      </div>
                      <p className="text-xs text-zinc-400">
                        Target:{" "}
                        <code className="text-zinc-200">
                          {asset ? asset.normalized_locator : a.asset_id}
                        </code>{" "}
                        · Window: {formatUtc(a.valid_from)} →{" "}
                        {formatUtc(a.expires_at)}
                      </p>
                      <p className="text-xs text-zinc-400">
                        Capabilities: {a.approved_activities.join(", ")}
                        {a.allowed_ports?.length
                          ? ` · Ports: ${a.allowed_ports.join(", ")}`
                          : " · Ports: default-for-scheme"}
                      </p>
                    </div>

                    <div className="flex flex-wrap gap-2">
                      {canRequest &&
                      a.status !== "revoked" &&
                      a.status !== "expired" ? (
                        <button
                          type="button"
                          onClick={() => startEdit(a)}
                          className="vf-btn-secondary px-3 py-1 text-xs"
                        >
                          Edit Scope
                        </button>
                      ) : null}
                      <button
                        type="button"
                        onClick={() =>
                          setExpandedHistory((prev) => ({
                            ...prev,
                            [a.id]: !historyOpen,
                          }))
                        }
                        className="vf-btn-secondary px-3 py-1 text-xs"
                      >
                        {historyOpen ? "Hide History" : "History"} (
                        {a.audit_history.length})
                      </button>
                      {a.status === "pending" && canApprove ? (
                        <>
                          <button
                            type="button"
                            disabled={isSelfRequest}
                            title={
                              isSelfRequest
                                ? "Separation of duties: requester cannot approve own request"
                                : "Approve authorization"
                            }
                            onClick={() => void handleDecision(a.id, "approve")}
                            className="vf-btn-primary px-3 py-1 text-xs"
                          >
                            {isSelfRequest ? "Self-Approval Blocked" : "Approve"}
                          </button>
                          <button
                            type="button"
                            onClick={() => void handleDecision(a.id, "reject")}
                            className="vf-btn-warning px-3 py-1 text-xs"
                          >
                            Reject
                          </button>
                        </>
                      ) : null}
                      {(a.status === "pending" || a.status === "approved") &&
                      canRevoke ? (
                        <button
                          type="button"
                          onClick={() => void handleDecision(a.id, "revoke")}
                          className="vf-btn-danger px-3 py-1 text-xs"
                        >
                          Revoke
                        </button>
                      ) : null}
                    </div>
                  </div>

                  {a.status === "pending" && canApprove && isSelfRequest ? (
                    <div className="mt-3.5 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-white/[0.075] bg-[#141419] px-4 py-3 text-xs text-zinc-300">
                      <div className="flex items-start gap-2.5">
                        <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-amber-400" />
                        <span className="leading-relaxed">
                          <strong className="font-medium text-zinc-100">
                            Separation of Duties (SoD):
                          </strong>{" "}
                          You submitted this authorization request, so policy blocks self-approval. Ask a second{" "}
                          <code className="text-zinc-200">owner</code> or{" "}
                          <code className="text-zinc-200">security_lead</code> to approve it (or have a{" "}
                          <code className="text-zinc-200">security_analyst</code> submit the request for you to approve).
                        </span>
                      </div>
                      <Link
                        href={`/organizations/${orgId}/members`}
                        className="vf-btn-secondary rounded-full px-3.5 py-1 text-[11px]"
                      >
                        Manage Members →
                      </Link>
                    </div>
                  ) : null}

                  {authSnapshots.length > 0 ? (
                    <div className="mt-3 space-y-2 border-t border-white/[0.07] pt-3">
                      <div className="text-xs font-medium text-zinc-300">
                        Immutable Signed Scope Snapshots ({authSnapshots.length})
                      </div>
                      {authSnapshots.map((snap) => {
                        const vr = verifyResults[snap.id];
                        return (
                          <div
                            key={snap.id}
                            className="rounded border border-white/[0.068] bg-[#141417] p-2.5 text-xs"
                          >
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <span className="font-mono text-zinc-300">
                                v{snap.snapshot_version} · asset v
                                {snap.asset_version} · key {snap.signing_key_id} ·
                                sha256:{snap.payload_sha256.slice(0, 16)}...
                              </span>
                              {canVerifySnapshot ? (
                                <button
                                  type="button"
                                  onClick={() =>
                                    void handleVerifySnapshot(snap.id)
                                  }
                                  className="vf-btn-secondary h-6 px-2.5 text-[11px]"
                                >
                                  Verify Snapshot &amp; DNS
                                </button>
                              ) : null}
                            </div>
                            {snap.resolved_ips.length > 0 ? (
                              <div className="mt-1 text-zinc-400">
                                Pinned IPs: {snap.resolved_ips.join(", ")}
                              </div>
                            ) : null}
                            {vr ? (
                              <div
                                className={`mt-2 rounded border p-2 ${
                                  vr.valid
                                    ? "border-white/[0.08] bg-[#121614] text-zinc-200"
                                    : "border-white/[0.08] bg-[#131317] text-zinc-200"
                                }`}
                              >
                                <div className="font-medium">
                                  Verification:{" "}
                                  {vr.valid ? "VALID" : "INVALID"} (OPA:{" "}
                                  {vr.opa_outcome} · sig: {vr.signature_reason})
                                </div>
                                <ul className="mt-1 list-disc pl-4">
                                  {vr.reasons.map((r) => (
                                    <li key={r.code}>
                                      <code className="font-semibold">
                                        {r.code}
                                      </code>
                                      : {r.message}
                                    </li>
                                  ))}
                                </ul>
                              </div>
                            ) : null}
                          </div>
                        );
                      })}
                    </div>
                  ) : null}

                  {historyOpen ? (
                    <div className="mt-3 space-y-1.5 border-t border-white/[0.07] pt-3 text-xs text-zinc-400">
                      {a.audit_history.map((ev, idx) => (
                        <div key={idx} className="font-mono">
                          [{String(ev.timestamp || "")}]{" "}
                          <span className="text-zinc-200">
                            {String(ev.event || "")}
                          </span>{" "}
                          {ev.reason ? `— ${String(ev.reason)}` : ""}
                        </div>
                      ))}
                    </div>
                  ) : null}
                </div>
              );
            })}
          </div>
        )}
      </section>

      {canRequest ? (
        <section className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-6">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-medium text-white">
              {editingId ? "Edit Authorization Scope" : "Request Authorization"}
            </h2>
            {editingId ? (
              <button
                type="button"
                onClick={resetForm}
                className="vf-btn-secondary px-3 py-1 text-xs"
              >
                Cancel Edit
              </button>
            ) : null}
          </div>
          {assets.length === 0 ? (
            <p className="mt-2 text-sm text-amber-300">
              Register at least one asset before requesting testing authorization.
            </p>
          ) : (
            <form
              onSubmit={handleSubmit}
              className="mt-4 grid gap-4 sm:grid-cols-2"
            >
              <div>
                <label className="block text-xs text-zinc-300">
                  Target Asset
                </label>
                <Select
                  value={assetId}
                  disabled={Boolean(editingId)}
                  onChange={(e) => setAssetId(e.target.value)}
                  className="mt-1"
                >
                  {assets.map((asset) => (
                    <option key={asset.id} value={asset.id}>
                      [{asset.asset_type}] {asset.normalized_locator} (v
                      {asset.version ?? 1})
                    </option>
                  ))}
                </Select>
              </div>
              <div>
                <label className="block text-xs text-zinc-300">
                  Authorization Reference / Ticket ID
                </label>
                <input
                  type="text"
                  required
                  minLength={2}
                  value={reference}
                  onChange={(e) => setReference(e.target.value)}
                  placeholder="CAB-2026-0412"
                  className="mt-1 vf-input"
                />
              </div>
              <div>
                <label className="block text-xs text-zinc-300">
                  Permitted Intensity
                </label>
                <Select
                  value={permittedIntensity}
                  onChange={(e) =>
                    setPermittedIntensity(e.target.value as IntensityLevel)
                  }
                  className="mt-1"
                >
                  {INTENSITY_LEVELS.map((lvl) => (
                    <option key={lvl} value={lvl}>
                      {lvl}
                    </option>
                  ))}
                </Select>
              </div>
              <div>
                <label className="block text-xs text-zinc-300">
                  Allowed Ports (comma-separated, optional)
                </label>
                <input
                  type="text"
                  value={allowedPorts}
                  onChange={(e) => setAllowedPorts(e.target.value)}
                  placeholder="443, 8443"
                  className="mt-1 vf-input"
                />
              </div>
              <div>
                <label className="block text-xs text-zinc-300">
                  Domain Match Mode
                </label>
                <Select
                  value={domainMatchMode}
                  onChange={(e) =>
                    setDomainMatchMode(
                      e.target.value as "exact_domain" | "domain_and_subdomains",
                    )
                  }
                  className="mt-1"
                >
                  <option value="exact_domain">exact_domain</option>
                  <option value="domain_and_subdomains">
                    domain_and_subdomains
                  </option>
                </Select>
              </div>
              <div>
                <label className="block text-xs text-zinc-300">
                  URL Match Mode
                </label>
                <Select
                  value={urlMatchMode}
                  onChange={(e) =>
                    setUrlMatchMode(
                      e.target.value as "exact_url" | "url_path_prefix",
                    )
                  }
                  className="mt-1"
                >
                  <option value="url_path_prefix">url_path_prefix</option>
                  <option value="exact_url">exact_url</option>
                </Select>
              </div>
              <div>
                <label className="block text-xs text-zinc-300">
                  Additional In-Scope Domains (comma-separated)
                </label>
                <input
                  type="text"
                  value={extraDomains}
                  onChange={(e) => setExtraDomains(e.target.value)}
                  placeholder="api.example.com"
                  className="mt-1 vf-input"
                />
              </div>
              <div>
                <label className="block text-xs text-zinc-300">
                  Additional In-Scope IPs (comma-separated)
                </label>
                <input
                  type="text"
                  value={extraIps}
                  onChange={(e) => setExtraIps(e.target.value)}
                  placeholder="93.184.216.34"
                  className="mt-1 vf-input"
                />
              </div>
              <div>
                <label className="block text-xs text-zinc-300">
                  Additional In-Scope CIDRs (comma-separated)
                </label>
                <input
                  type="text"
                  value={extraCidrs}
                  onChange={(e) => setExtraCidrs(e.target.value)}
                  placeholder="10.20.0.0/24"
                  className="mt-1 vf-input"
                />
              </div>
              <div>
                <label className="block text-xs text-zinc-300">
                  Validity Window (hours from now)
                </label>
                <input
                  type="number"
                  min={1}
                  max={8760}
                  value={validHours}
                  onChange={(e) =>
                    setValidHours(Number.parseInt(e.target.value, 10) || 24)
                  }
                  className="mt-1 vf-input"
                />
              </div>
              <div className="flex flex-wrap gap-6 sm:col-span-2">
                <label className="flex items-center gap-2 text-xs text-zinc-200">
                  <input
                    type="checkbox"
                    checked={allowPrivateNetworks}
                    onChange={(e) => setAllowPrivateNetworks(e.target.checked)}
                  />
                  Allow explicitly registered private IP/CIDR ranges (RFC1918)
                </label>
                <label className="flex items-center gap-2 text-xs text-zinc-200">
                  <input
                    type="checkbox"
                    checked={productionActiveApproved}
                    onChange={(e) =>
                      setProductionActiveApproved(e.target.checked)
                    }
                  />
                  Elevated sign-off for active testing in production
                </label>
              </div>
              <div className="sm:col-span-2">
                <span className="block text-xs text-zinc-300">
                  Approved Testing Capabilities
                </span>
                <div className="mt-2 flex flex-wrap gap-2">
                  {TESTING_CAPABILITIES.map((cap) => {
                    const checked = selectedCapabilities.includes(cap);
                    return (
                      <label
                        key={cap}
                        className={`cursor-pointer rounded border px-2.5 py-1 text-xs ${
                          checked
                            ? "border-white/[0.08] bg-[#1a1a1f] text-zinc-200"
                            : "border-white/[0.1] bg-[#0e0e11] text-zinc-300"
                        }`}
                      >
                        <input
                          type="checkbox"
                          className="mr-1.5"
                          checked={checked}
                          onChange={() => toggleCapability(cap)}
                        />
                        {cap}
                      </label>
                    );
                  })}
                </div>
              </div>
              <div className="sm:col-span-2">
                <button
                  type="submit"
                  disabled={submitting}
                  className="vf-btn-primary h-8 px-4 text-xs"
                >
                  {submitting
                    ? "Saving..."
                    : editingId
                      ? "Save Changes & Request Re-Approval"
                      : "Submit Authorization Request"}
                </button>
              </div>
            </form>
          )}
        </section>
      ) : null}
    </div>
  );
}

export default function AuthorizationsPage() {
  const params = useParams<{ orgId: string }>();
  return (
    <OrgShell orgId={params.orgId}>
      {({ auth, membership }) => (
        <AuthorizationsContent
          orgId={params.orgId}
          currentUserId={auth.user.id}
          canRequest={hasPermission(membership, "authorization:request")}
          canApprove={hasPermission(membership, "authorization:approve")}
          canRevoke={hasPermission(membership, "authorization:revoke")}
          canVerifySnapshot={hasPermission(membership, "snapshot:verify")}
          csrfToken={auth.csrf_token}
        />
      )}
    </OrgShell>
  );
}
