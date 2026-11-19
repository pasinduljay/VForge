"use client";

import { useParams } from "next/navigation";
import { FormEvent, useCallback, useEffect, useState } from "react";
import OrgShell, { hasPermission } from "@/components/OrgShell";
import { Select } from "@/components/ui/Select";
import { apiFetch, formatUtc } from "@/lib/api";
import {
  INTENSITY_LEVELS,
  TARGET_TYPES,
  TESTING_CAPABILITIES,
  TOOL_CATEGORIES,
  type Asset,
  type Authorization,
  type IntensityLevel,
  type PaginatedResponse,
  type ScopeEvaluationResponse,
  type ScopeSnapshot,
  type SnapshotVerifyResponse,
  type TargetType,
} from "@/lib/types";

function ScopePolicyContent({
  orgId,
  canEvaluate,
  canVerify,
  csrfToken,
}: {
  orgId: string;
  canEvaluate: boolean;
  canVerify: boolean;
  csrfToken: string | null;
}) {
  const [authorizations, setAuthorizations] = useState<Authorization[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [snapshots, setSnapshots] = useState<ScopeSnapshot[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [authorizationId, setAuthorizationId] = useState("");
  const [targetType, setTargetType] = useState<TargetType>("exact_url");
  const [rawTarget, setRawTarget] = useState("");
  const [redirectLocation, setRedirectLocation] = useState("");
  const [requestedCaps, setRequestedCaps] = useState<string[]>([
    "passive_web_testing",
  ]);
  const [requestedIntensity, setRequestedIntensity] =
    useState<IntensityLevel>("passive");
  const [toolCategory, setToolCategory] = useState("");
  const [resolveDns, setResolveDns] = useState(false);
  const [evaluating, setEvaluating] = useState(false);
  const [evaluation, setEvaluation] = useState<ScopeEvaluationResponse | null>(
    null,
  );
  const [verifyMap, setVerifyMap] = useState<
    Record<string, SnapshotVerifyResponse>
  >({});

  const fetchData = useCallback(async () => {
    const [authRes, assetRes, snapRes] = await Promise.all([
      apiFetch<PaginatedResponse<Authorization>>(
        `/api/v1/organizations/${orgId}/authorizations?limit=100`,
      ),
      apiFetch<PaginatedResponse<Asset>>(
        `/api/v1/organizations/${orgId}/assets?limit=100`,
      ),
      apiFetch<PaginatedResponse<ScopeSnapshot>>(
        `/api/v1/organizations/${orgId}/snapshots?limit=100`,
      ).catch(() => ({ items: [] as ScopeSnapshot[], total: 0, limit: 100, offset: 0 })),
    ]);
    return { authRes, assetRes, snapRes };
  }, [orgId]);

  useEffect(() => {
    let active = true;
    void fetchData()
      .then(({ authRes, assetRes, snapRes }) => {
        if (!active) return;
        setAuthorizations(authRes.items);
        setAssets(assetRes.items);
        setSnapshots(snapRes.items);
        if (authRes.items.length > 0) {
          const firstAuth = authRes.items[0];
          setAuthorizationId(firstAuth.id);
          const matchedAsset = assetRes.items.find(
            (item) => item.id === firstAuth.asset_id,
          );
          if (matchedAsset) {
            setRawTarget(matchedAsset.normalized_locator);
          }
        }
        setLoading(false);
      })
      .catch((err) => {
        if (!active) return;
        setError(
          err instanceof Error ? err.message : "Failed to load scope state",
        );
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [fetchData]);

  const toggleCap = (cap: string) => {
    setRequestedCaps((prev) =>
      prev.includes(cap) ? prev.filter((item) => item !== cap) : [...prev, cap],
    );
  };

  const handleEvaluate = async (e: FormEvent) => {
    e.preventDefault();
    if (!authorizationId || !rawTarget.trim()) {
      setError("Authorization and target are required.");
      return;
    }
    setEvaluating(true);
    setError(null);
    try {
      const result = await apiFetch<ScopeEvaluationResponse>(
        `/api/v1/organizations/${orgId}/scope/evaluate`,
        {
          method: "POST",
          csrfToken,
          body: JSON.stringify({
            authorization_id: authorizationId,
            target_type: targetType,
            raw_target: rawTarget.trim(),
            requested_capabilities: requestedCaps,
            requested_intensity: requestedIntensity,
            tool_category: toolCategory || null,
            redirect_location: redirectLocation.trim() || null,
            resolve_dns: resolveDns,
          }),
        },
      );
      setEvaluation(result);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Scope evaluation request failed",
      );
    } finally {
      setEvaluating(false);
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
          body: JSON.stringify({ revalidate_dns: resolveDns }),
        },
      );
      setVerifyMap((prev) => ({ ...prev, [snapshotId]: res }));
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Snapshot verification failed",
      );
    }
  };

  return (
    <div className="space-y-8">
      <div>
        <div className="mb-1 text-[11px] font-semibold uppercase tracking-[0.12em] text-blue-400">
          Scan Rules &amp; Safety Dry-Run
        </div>
        <h1 className="text-2xl font-semibold text-white">
          Target Scope Check
        </h1>
        <p className="mt-1 text-sm text-zinc-400">
          Test whether a URL, domain, or IP matches an approved Scan Approval before starting a real scan. Useful for troubleshooting blocked targets.
        </p>
      </div>

      {error ? (
        <div className="rounded-md border border-white/[0.08] bg-[#131317] p-4 text-sm text-zinc-200">
          {error}
        </div>
      ) : null}

      {loading ? (
        <p className="text-sm text-zinc-400">Loading scope policies...</p>
      ) : (
        <>
          {canEvaluate ? (
            <section className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-6">
              <h2 className="text-lg font-medium text-white">
                Evaluate Target &amp; Policy Decision
              </h2>
              {authorizations.length === 0 ? (
                <p className="mt-2 text-sm text-amber-300">
                  Create an authorization first to evaluate targets against it.
                </p>
              ) : (
                <form
                  onSubmit={handleEvaluate}
                  className="mt-4 grid gap-4 sm:grid-cols-2"
                >
                  <div>
                    <label className="block text-xs text-zinc-300">
                      Authorization Record
                    </label>
                    <Select
                      value={authorizationId}
                      onChange={(e) => setAuthorizationId(e.target.value)}
                      className="mt-1"
                    >
                      {authorizations.map((a) => {
                        const asset = assets.find(
                          (item) => item.id === a.asset_id,
                        );
                        return (
                          <option key={a.id} value={a.id}>
                            [{a.status}] {a.authorization_reference} —{" "}
                            {asset ? asset.normalized_locator : a.asset_id}
                          </option>
                        );
                      })}
                    </Select>
                  </div>
                  <div>
                    <label className="block text-xs text-zinc-300">
                      Target Type
                    </label>
                    <Select
                      value={targetType}
                      onChange={(e) =>
                        setTargetType(e.target.value as TargetType)
                      }
                      className="mt-1"
                    >
                      {TARGET_TYPES.map((tt) => (
                        <option key={tt} value={tt}>
                          {tt}
                        </option>
                      ))}
                    </Select>
                  </div>
                  <div>
                    <label className="block text-xs text-zinc-300">
                      Proposed Target (URL, Domain, IP, CIDR, Repo, Image)
                    </label>
                    <input
                      type="text"
                      required
                      value={rawTarget}
                      onChange={(e) => setRawTarget(e.target.value)}
                      placeholder="https://app.example.com/api/v1"
                      className="mt-1 vf-input"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-zinc-300">
                      Redirect Destination to Pre-Check (optional)
                    </label>
                    <input
                      type="text"
                      value={redirectLocation}
                      onChange={(e) => setRedirectLocation(e.target.value)}
                      placeholder="https://app.example.com/login"
                      className="mt-1 vf-input"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-zinc-300">
                      Requested Intensity
                    </label>
                    <Select
                      value={requestedIntensity}
                      onChange={(e) =>
                        setRequestedIntensity(e.target.value as IntensityLevel)
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
                      Approved Tool Category (optional)
                    </label>
                    <Select
                      value={toolCategory}
                      onChange={(e) => setToolCategory(e.target.value)}
                      className="mt-1"
                    >
                      {TOOL_CATEGORIES.map((cat) => (
                        <option key={cat || "none"} value={cat}>
                          {cat || "(unspecified)"}
                        </option>
                      ))}
                    </Select>
                  </div>
                  <div className="sm:col-span-2">
                    <span className="block text-xs text-zinc-300">
                      Requested Capabilities
                    </span>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {TESTING_CAPABILITIES.map((cap) => {
                        const checked = requestedCaps.includes(cap);
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
                              onChange={() => toggleCap(cap)}
                            />
                            {cap}
                          </label>
                        );
                      })}
                    </div>
                  </div>
                  <div className="sm:col-span-2">
                    <label className="flex items-center gap-2 text-xs text-zinc-200">
                      <input
                        type="checkbox"
                        checked={resolveDns}
                        onChange={(e) => setResolveDns(e.target.checked)}
                      />
                      Resolve live A/AAAA DNS records and check against pinned
                      snapshot &amp; SSRF/metadata policy
                    </label>
                  </div>
                  <div className="sm:col-span-2">
                    <button
                      type="submit"
                      disabled={evaluating}
                      className="vf-btn-primary h-8 px-4 text-xs"
                    >
                      {evaluating
                        ? "Evaluating with OPA..."
                        : "Evaluate Policy Decision"}
                    </button>
                  </div>
                </form>
              )}

              {evaluation ? (
                <div
                  className={`mt-6 rounded-lg border p-4 ${
                    evaluation.outcome === "ALLOW"
                      ? "border-[#3b72f2]/45 bg-[#162033]/60"
                      : evaluation.outcome === "REQUIRES_APPROVAL"
                        ? "border-white/[0.08] bg-[#131317]"
                        : "border-white/[0.08] bg-[#131317]"
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-sm font-semibold text-white">
                      Policy Outcome: {evaluation.outcome}
                    </span>
                    <span className="text-xs text-zinc-300">
                      policy_version: {evaluation.policy_version}
                    </span>
                  </div>
                  <div className="mt-2 grid gap-2 text-xs text-zinc-300 sm:grid-cols-2">
                    <div>
                      Canonical Target:{" "}
                      <code className="text-white">
                        {evaluation.canonical_target ?? "(rejected)"}
                      </code>
                    </div>
                    <div>
                      Port: {evaluation.target_port ?? "(scheme default)"} ·
                      Redirect Safe: {evaluation.redirect_safe ? "yes" : "no"}
                    </div>
                    <div>
                      Resolved IPs:{" "}
                      {evaluation.resolved_ips.length > 0
                        ? evaluation.resolved_ips.join(", ")
                        : "(none)"}
                    </div>
                    <div>
                      Snapshot Verified:{" "}
                      {evaluation.snapshot_verified === null ||
                      evaluation.snapshot_verified === undefined
                        ? "N/A"
                        : evaluation.snapshot_verified
                          ? "valid"
                          : "INVALID"}
                    </div>
                  </div>
                  <div className="mt-3">
                    <div className="text-xs font-medium text-zinc-200">
                      Structured Policy Reasons:
                    </div>
                    <ul className="mt-1 list-disc space-y-1 pl-5 text-xs text-zinc-200">
                      {evaluation.reasons.map((r) => (
                        <li key={r.code}>
                          <code className="font-semibold">{r.code}</code>:{" "}
                          {r.message}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              ) : null}
            </section>
          ) : null}

          <section className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-6">
            <h2 className="text-lg font-medium text-white">
              Immutable Signed Scope Snapshots ({snapshots.length})
            </h2>
            {snapshots.length === 0 ? (
              <p className="mt-3 text-sm text-zinc-400">
                No signed scope snapshots have been issued yet. Approve an
                authorization to generate its first signed snapshot.
              </p>
            ) : (
              <div className="mt-4 space-y-3">
                {snapshots.map((snap) => {
                  const vr = verifyMap[snap.id];
                  return (
                    <div
                      key={snap.id}
                      className="rounded border border-white/[0.068] bg-[#0e0e11] p-4 text-xs"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="font-medium text-white">
                          {snap.canonical_locator} (snapshot v
                          {snap.snapshot_version} · asset v{snap.asset_version})
                        </div>
                        {canVerify ? (
                          <button
                            type="button"
                            onClick={() => void handleVerifySnapshot(snap.id)}
                            className="vf-btn-secondary h-7 px-3 text-xs"
                          >
                            Verify Integrity &amp; Policy
                          </button>
                        ) : null}
                      </div>
                      <p className="mt-1 text-zinc-400">
                        Capabilities: {snap.permitted_capabilities.join(", ")} ·
                        Intensity: {snap.permitted_intensity} · Expires:{" "}
                        {formatUtc(snap.authorization_expires_at)}
                      </p>
                      <p className="mt-1 font-mono text-zinc-400">
                        {snap.signature_algorithm} ({snap.signing_key_id}) ·
                        sha256: {snap.payload_sha256}
                      </p>
                      {vr ? (
                        <div
                          className={`mt-2 rounded border p-2 ${
                            vr.valid
                              ? "border-white/[0.08] bg-[#121614] text-zinc-200"
                              : "border-white/[0.08] bg-[#131317] text-zinc-200"
                          }`}
                        >
                          <div>
                            Valid: {vr.valid ? "true" : "false"} · OPA:{" "}
                            {vr.opa_outcome} · Policy current:{" "}
                            {vr.policy_version_current ? "yes" : "no"} · Asset
                            current: {vr.asset_version_current ? "yes" : "no"}
                          </div>
                          <ul className="mt-1 list-disc pl-4">
                            {vr.reasons.map((r) => (
                              <li key={r.code}>
                                <code>{r.code}</code>: {r.message}
                              </li>
                            ))}
                          </ul>
                        </div>
                      ) : null}
                    </div>
                  );
                })}
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
}

export default function ScopePolicyPage() {
  const params = useParams<{ orgId: string }>();
  return (
    <OrgShell orgId={params.orgId}>
      {({ auth, membership }) => (
        <ScopePolicyContent
          orgId={params.orgId}
          canEvaluate={hasPermission(membership, "scope:evaluate")}
          canVerify={hasPermission(membership, "snapshot:verify")}
          csrfToken={auth.csrf_token}
        />
      )}
    </OrgShell>
  );
}
