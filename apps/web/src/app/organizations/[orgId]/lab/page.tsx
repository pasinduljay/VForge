"use client";

import { useParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";
import OrgShell, { hasPermission } from "@/components/OrgShell";
import { Select } from "@/components/ui/Select";
import { apiFetch, formatUtc } from "@/lib/api";
import type {
  LabChallengeItem,
  LabOverview,
  LabWorkspaceItem,
  OrganizationMembershipSummary,
} from "@/lib/types";

const TRACK_LEVELS = [
  "all",
  "beginner",
  "intermediate",
  "advanced",
  "expert_practice",
] as const;

const SAFE_ACTIONS = [
  "baseline_probe",
  "auth_token_check",
  "idor_read_check",
  "sqli_error_probe",
  "xss_reflection_probe",
  "remediation_retest",
] as const;

const SELF_SCAN_COMPONENTS = [
  "control_plane_api",
  "control_plane_web",
  "scanner_contracts",
  "runner_agent",
  "opa_policies",
] as const;

function LabContent({
  orgId,
  membership,
  csrfToken,
}: {
  orgId: string;
  membership: OrganizationMembershipSummary | null;
  csrfToken: string;
}) {
  const canRead = hasPermission(membership, "lab:read");
  const canPractice = hasPermission(membership, "lab:practice");
  const canManage = hasPermission(membership, "lab:manage");

  const [overview, setOverview] = useState<LabOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionMsg, setActionMsg] = useState<string | null>(null);

  const [trackFilter, setTrackFilter] =
    useState<(typeof TRACK_LEVELS)[number]>("all");
  const [selectedWorkspaceId, setSelectedWorkspaceId] = useState("");
  const [selectedChallengeId, setSelectedChallengeId] = useState("");

  // Provision workspace state
  const [envSlug, setEnvSlug] = useState("juice-crapi-sandbox");
  const [displayName, setDisplayName] = useState("AppSec Guided Lab");
  const [accountPrefix, setAccountPrefix] = useState("student");
  const [consentOnCreate, setConsentOnCreate] = useState(true);

  // Safe validation form state
  const [targetUrl, setTargetUrl] = useState("http://127.0.0.1:3100");
  const [toolSlug, setToolSlug] = useState("zap");
  const [actionType, setActionType] =
    useState<(typeof SAFE_ACTIONS)[number]>("baseline_probe");
  const [disposableIdentity, setDisposableIdentity] = useState("");
  const [observedEvidence, setObservedEvidence] = useState(
    "Verified challenge precondition safely in egress-denied lab.",
  );

  // Remediation form state
  const [remediationNotes, setRemediationNotes] = useState("");

  // Self-scan form state
  const [selfScanComponent, setSelfScanComponent] =
    useState<(typeof SELF_SCAN_COMPONENTS)[number]>("control_plane_api");
  const [selfScanProfile, setSelfScanProfile] = useState(
    "vforge-self-verify",
  );

  const encodedOrgId = encodeURIComponent(orgId);

  const applyDefaultsFromOverview = useCallback((data: LabOverview) => {
    setSelectedWorkspaceId((prev) => prev || (data.workspaces[0]?.id ?? ""));
    const defaultCh = data.challenges[0];
    setSelectedChallengeId((prev) => prev || (defaultCh?.id ?? ""));
    if (defaultCh) {
      setTargetUrl((prev) => prev || defaultCh.permitted_target);
      setToolSlug((prev) => prev || (defaultCh.permitted_tools_json[0] ?? "zap"));
    }
    const defaultIdent =
      data.workspaces[0]?.disposable_identities_json[0]?.handle ?? "";
    setDisposableIdentity((prev) => prev || defaultIdent);
  }, []);

  const loadOverview = useCallback(async () => {
    try {
      const data = await apiFetch<LabOverview>(
        `/api/v1/organizations/${encodedOrgId}/lab/overview`,
      );
      setOverview(data);
      applyDefaultsFromOverview(data);
      setError(null);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to load Learning Lab",
      );
    } finally {
      setLoading(false);
    }
  }, [encodedOrgId, applyDefaultsFromOverview]);

  useEffect(() => {
    if (!canRead) {
      return;
    }
    let active = true;
    void apiFetch<LabOverview>(
      `/api/v1/organizations/${encodedOrgId}/lab/overview`,
    )
      .then((data) => {
        if (!active) return;
        setOverview(data);
        applyDefaultsFromOverview(data);
        setError(null);
        setLoading(false);
      })
      .catch((err) => {
        if (!active) return;
        setError(
          err instanceof Error ? err.message : "Failed to load Learning Lab",
        );
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [encodedOrgId, applyDefaultsFromOverview, canRead]);

  const activeWorkspace: LabWorkspaceItem | null = useMemo(() => {
    if (!overview?.workspaces.length) return null;
    return (
      overview.workspaces.find((w) => w.id === selectedWorkspaceId) ??
      overview.workspaces[0]
    );
  }, [overview, selectedWorkspaceId]);

  const filteredChallenges: LabChallengeItem[] = useMemo(() => {
    const items = overview?.challenges ?? [];
    if (trackFilter === "all") return items;
    return items.filter((c) => c.track_level === trackFilter);
  }, [overview, trackFilter]);

  const activeChallenge: LabChallengeItem | null = useMemo(() => {
    if (!overview?.challenges.length) return null;
    return (
      overview.challenges.find((c) => c.id === selectedChallengeId) ??
      overview.challenges[0]
    );
  }, [overview, selectedChallengeId]);

  const activeProgress = useMemo(() => {
    if (!overview || !activeWorkspace || !activeChallenge) return null;
    return (
      overview.progress.find(
        (p) =>
          p.workspace_id === activeWorkspace.id &&
          p.challenge_id === activeChallenge.id,
      ) ?? null
    );
  }, [overview, activeWorkspace, activeChallenge]);

  const selectChallenge = (ch: LabChallengeItem) => {
    setSelectedChallengeId(ch.id);
    setTargetUrl(ch.permitted_target);
    setToolSlug(ch.permitted_tools_json[0] ?? "zap");
    setActionType("baseline_probe");
    setRemediationNotes("");
  };

  const handleProvisionWorkspace = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setActionMsg(null);
    try {
      const ws = await apiFetch<LabWorkspaceItem>(
        `/api/v1/organizations/${encodedOrgId}/lab/workspaces`,
        {
          method: "POST",
          csrfToken,
          body: JSON.stringify({
            environment_slug: envSlug,
            display_name: displayName,
            consent_to_persist_progress: consentOnCreate,
            disposable_account_prefix: accountPrefix,
          }),
        },
      );
      setSelectedWorkspaceId(ws.id);
      setDisposableIdentity(ws.disposable_identities_json[0]?.handle ?? "");
      setActionMsg(`Provisioned isolated lab workspace '${ws.environment_slug}'.`);
      await loadOverview();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to provision lab workspace",
      );
    } finally {
      setBusy(false);
    }
  };

  const handleToggleConsent = async () => {
    if (!activeWorkspace) return;
    setBusy(true);
    setError(null);
    setActionMsg(null);
    try {
      const nextValue = !activeWorkspace.consent_to_persist_progress;
      await apiFetch<LabWorkspaceItem>(
        `/api/v1/organizations/${encodedOrgId}/lab/workspaces/${encodeURIComponent(activeWorkspace.id)}/consent`,
        {
          method: "POST",
          csrfToken,
          body: JSON.stringify({ consent_to_persist_progress: nextValue }),
        },
      );
      setActionMsg(
        nextValue
          ? "Progress persistence consent enabled for this workspace."
          : "Progress persistence consent revoked (stateless mode).",
      );
      await loadOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update consent");
    } finally {
      setBusy(false);
    }
  };

  const handleResetWorkspace = async () => {
    if (!activeWorkspace) return;
    setBusy(true);
    setError(null);
    setActionMsg(null);
    try {
      const ws = await apiFetch<LabWorkspaceItem>(
        `/api/v1/organizations/${encodedOrgId}/lab/workspaces/${encodeURIComponent(activeWorkspace.id)}/reset`,
        {
          method: "POST",
          csrfToken,
        },
      );
      setDisposableIdentity(ws.disposable_identities_json[0]?.handle ?? "");
      setActionMsg(
        `Reset workspace '${ws.environment_slug}' to clean epoch #${ws.reset_epoch} with rotated disposable accounts.`,
      );
      await loadOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to reset workspace");
    } finally {
      setBusy(false);
    }
  };

  const handleValidateChallenge = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeWorkspace || !activeChallenge) return;
    setBusy(true);
    setError(null);
    setActionMsg(null);
    try {
      const identToUse =
        disposableIdentity ||
        activeWorkspace.disposable_identities_json[0]?.handle ||
        "";
      await apiFetch(
        `/api/v1/organizations/${encodedOrgId}/lab/workspaces/${encodeURIComponent(activeWorkspace.id)}/validate`,
        {
          method: "POST",
          csrfToken,
          body: JSON.stringify({
            challenge_id: activeChallenge.id,
            target_url: targetUrl,
            tool_slug: toolSlug,
            action_type: actionType,
            disposable_identity_used: identToUse,
            observed_evidence: observedEvidence,
          }),
        },
      );
      setActionMsg(
        `Executed bounded '${actionType}' safely on '${activeChallenge.slug}'.`,
      );
      await loadOverview();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Safe validation rejected",
      );
    } finally {
      setBusy(false);
    }
  };

  const handleRecordRemediation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeWorkspace || !activeChallenge) return;
    setBusy(true);
    setError(null);
    setActionMsg(null);
    try {
      await apiFetch(
        `/api/v1/organizations/${encodedOrgId}/lab/workspaces/${encodeURIComponent(activeWorkspace.id)}/remediate`,
        {
          method: "POST",
          csrfToken,
          body: JSON.stringify({
            challenge_id: activeChallenge.id,
            remediation_notes: remediationNotes,
          }),
        },
      );
      setActionMsg(
        "Recorded remediation notes. Run 'remediation_retest' next to verify the fix.",
      );
      setActionType("remediation_retest");
      await loadOverview();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to record remediation",
      );
    } finally {
      setBusy(false);
    }
  };

  const handleRunSelfScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setActionMsg(null);
    try {
      await apiFetch(`/api/v1/organizations/${encodedOrgId}/lab/self-scans`, {
        method: "POST",
        csrfToken,
        body: JSON.stringify({
          target_component: selfScanComponent,
          profile_name: selfScanProfile,
        }),
      });
      setActionMsg(
        `Completed VForge self-verification scan for '${selfScanComponent}'.`,
      );
      await loadOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Self-scan failed");
    } finally {
      setBusy(false);
    }
  };

  if (!canRead) {
    return (
      <div className="rounded-lg border border-white/[0.08] bg-[#131317] p-6 text-zinc-200">
        Your role does not include <code className="font-mono">lab:read</code>{" "}
        permission.
      </div>
    );
  }

  if (loading) {
    return <p className="text-sm text-zinc-400">Loading Learning Lab…</p>;
  }

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-white">
            Isolated Learning Lab & Self-Verification
          </h1>
          <p className="mt-1 text-sm text-zinc-400">
            Opt-in egress-denied vulnerable targets (Juice Shop, cRAPI, WebGoat),
            consent-gated tracks, and VForge control-plane self-scans.
          </p>
        </div>
        {overview?.compose_isolation && (
          <div
            className={`rounded-lg border px-4 py-2 text-xs ${
              overview.compose_isolation.verified
                ? "border-white/[0.08] bg-[#121614] text-zinc-200"
                : "border-white/[0.08] bg-[#131317] text-zinc-200"
            }`}
          >
            <div className="font-semibold">
              Lab Compose Isolation:{" "}
              {overview.compose_isolation.verified
                ? "VERIFIED (internal: true, loopback-only)"
                : "VIOLATION DETECTED"}
            </div>
            <div className="mt-0.5 text-zinc-300">
              Pinned services checked: {overview.compose_isolation.services_checked}
            </div>
          </div>
        )}
      </div>

      {error && (
        <div className="rounded-lg border border-white/[0.08] bg-[#131317] px-4 py-3 text-sm text-zinc-200">
          {error}
        </div>
      )}
      {actionMsg && (
        <div className="rounded-lg border border-white/[0.08] bg-[#121614] px-4 py-3 text-sm text-zinc-200">
          {actionMsg}
        </div>
      )}

      {/* Workspace Isolation & Disposable Identity Management */}
      <section className="grid gap-6 lg:grid-cols-2">
        <div className="rounded-xl border border-white/[0.068] bg-[#141417] p-5">
          <h2 className="text-lg font-medium text-white">
            Isolated Lab Workspaces
          </h2>
          {activeWorkspace ? (
            <div className="mt-4 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="min-w-0 flex-1">
                  <Select
                    aria-label="Active lab workspace"
                    size="sm"
                    value={activeWorkspace.id}
                    onChange={(e) => {
                      const nextId = e.target.value;
                      setSelectedWorkspaceId(nextId);
                      const ws = overview?.workspaces.find((w) => w.id === nextId);
                      setDisposableIdentity(
                        ws?.disposable_identities_json[0]?.handle ?? "",
                      );
                    }}
                  >
                    {(overview?.workspaces ?? []).map((w) => (
                      <option key={w.id} value={w.id}>
                        {w.display_name} ({w.environment_slug}) — epoch #{w.reset_epoch}
                      </option>
                    ))}
                  </Select>
                </div>
                {canManage && (
                  <div className="flex gap-2">
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => void handleToggleConsent()}
                      className="vf-btn-secondary px-3 py-1.5 text-xs"
                    >
                      {activeWorkspace.consent_to_persist_progress
                        ? "Revoke Progress Consent"
                        : "Grant Progress Consent"}
                    </button>
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => void handleResetWorkspace()}
                      className="vf-btn-warning px-3 py-1.5 text-xs font-medium"
                    >
                      Reset Lab State
                    </button>
                  </div>
                )}
              </div>

              <div className="grid grid-cols-1 gap-3 text-xs text-zinc-300 sm:grid-cols-2">
                <div className="rounded-md border border-white/[0.068] bg-[#0e0e11] p-2.5">
                  <div className="text-zinc-400">Isolation Network</div>
                  <div className="mt-0.5 font-mono text-white">
                    {activeWorkspace.isolation_network_name}
                  </div>
                </div>
                <div className="rounded-md border border-white/[0.068] bg-[#0e0e11] p-2.5">
                  <div className="text-zinc-400">Progress Consent</div>
                  <div className="mt-0.5 font-semibold text-white">
                    {activeWorkspace.consent_to_persist_progress
                      ? "Granted (persisted)"
                      : "Disabled (stateless)"}
                  </div>
                </div>
              </div>

              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wide text-zinc-400">
                  Disposable Epoch #{activeWorkspace.reset_epoch} Test Accounts
                </h3>
                <ul className="mt-2 space-y-1.5 text-xs">
                  {activeWorkspace.disposable_identities_json.map((ident) => (
                    <li
                      key={ident.handle}
                      className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-white/[0.068] bg-[#0e0e11] px-3 py-2 font-mono text-zinc-200"
                    >
                      <span>{ident.handle}</span>
                      <span className="text-zinc-400">
                        {ident.role}
                        {canPractice && ident.credential_hint
                          ? ` · ${ident.credential_hint}`
                          : ""}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          ) : (
            <p className="mt-3 text-sm text-zinc-400">
              No isolated lab workspace provisioned yet for this organization.
            </p>
          )}
        </div>

        {canManage && (
          <form
            onSubmit={(e) => void handleProvisionWorkspace(e)}
            className="rounded-xl border border-white/[0.068] bg-[#141417] p-5 space-y-3"
          >
            <h2 className="text-lg font-medium text-white">
              Provision Disposable Lab Workspace
            </h2>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="block text-xs text-zinc-300">
                Environment Slug
                <input
                  value={envSlug}
                  onChange={(e) => setEnvSlug(e.target.value)}
                  className="mt-1 vf-input"
                  required
                />
              </label>
              <label className="block text-xs text-zinc-300">
                Display Name
                <input
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  className="mt-1 vf-input"
                  required
                />
              </label>
            </div>
            <label className="block text-xs text-zinc-300">
              Disposable Account Prefix
              <input
                value={accountPrefix}
                onChange={(e) => setAccountPrefix(e.target.value)}
                className="mt-1 vf-input"
                required
              />
            </label>
            <label className="flex items-center gap-2 text-xs text-zinc-200">
              <input
                type="checkbox"
                checked={consentOnCreate}
                onChange={(e) => setConsentOnCreate(e.target.checked)}
              />
              Consent to persist challenge progress & remediation verification
            </label>
            <button
              type="submit"
              disabled={busy}
              className="vf-btn-primary h-8 px-4 text-xs"
            >
              Provision Isolated Workspace
            </button>
          </form>
        )}
      </section>

      {/* Guided Curriculum */}
      <section className="rounded-xl border border-white/[0.068] bg-[#141417] p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-lg font-medium text-white">
            Guided Learning Tracks
          </h2>
          <div className="flex flex-wrap gap-2">
            {TRACK_LEVELS.map((lvl) => (
              <button
                key={lvl}
                type="button"
                onClick={() => setTrackFilter(lvl)}
                className={`rounded-md px-3 py-1 text-xs font-medium capitalize ${
                  trackFilter === lvl
                    ? "vf-btn-primary"
                    : "border border-white/[0.08] text-zinc-300 hover:bg-white/[0.06]"
                }`}
              >
                {lvl.replace("_", " ")}
              </button>
            ))}
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          {filteredChallenges.map((ch) => {
            const isSelected = activeChallenge?.id === ch.id;
            const prog = overview?.progress.find(
              (p) =>
                p.workspace_id === activeWorkspace?.id && p.challenge_id === ch.id,
            );
            return (
              <button
                key={ch.id}
                type="button"
                onClick={() => selectChallenge(ch)}
                className={`text-left rounded-lg border p-4 transition ${
                  isSelected
                    ? "border-[#3b72f2]/60 bg-[#141923]"
                    : "border-white/[0.068] bg-[#0e0e11]/50 hover:border-white/[0.08]"
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="rounded bg-[#1c1c20] px-2 py-0.5 text-xs font-mono text-[#93c5fd]">
                    {ch.track_level}
                  </span>
                  <span className="text-xs text-zinc-400">
                    {ch.cwe_id} · {ch.target_app}
                  </span>
                </div>
                <h3 className="mt-2 font-medium text-white">{ch.title}</h3>
                <p className="mt-1 text-xs text-zinc-400 line-clamp-2">
                  {ch.learning_goal}
                </p>
                {prog && (
                  <div className="mt-2 text-xs text-zinc-200">
                    Status: {prog.status} (attempts: {prog.attempts_count})
                  </div>
                )}
              </button>
            );
          })}
        </div>

        {activeChallenge && (
          <div className="grid gap-6 border-t border-white/[0.08] pt-5 lg:grid-cols-2">
            <div className="space-y-3 text-sm text-zinc-300">
              <h3 className="text-base font-semibold text-white">
                {activeChallenge.title} ({activeChallenge.cwe_id})
              </h3>
              <p>{activeChallenge.explanation}</p>
              <div>
                <div className="text-xs font-semibold uppercase text-zinc-400">
                  Preconditions
                </div>
                <ul className="mt-1 list-disc pl-5 text-xs space-y-1">
                  {activeChallenge.preconditions_json.map((pre) => (
                    <li key={pre}>{pre}</li>
                  ))}
                </ul>
              </div>
              <div className="rounded-md border border-white/[0.068] bg-[#0e0e11] p-3 text-xs">
                <div>
                  <span className="text-zinc-400">Permitted target: </span>
                  <span className="font-mono text-[#93c5fd]">
                    {activeChallenge.permitted_target}
                  </span>
                </div>
                <div className="mt-1">
                  <span className="text-zinc-400">Safe evidence criteria: </span>
                  {activeChallenge.safe_evidence_criteria}
                </div>
                <div className="mt-1">
                  <span className="text-zinc-400">Remediation exercise: </span>
                  {activeChallenge.remediation_exercise}
                </div>
                <div className="mt-1">
                  <span className="text-zinc-400">Retest instructions: </span>
                  {activeChallenge.retest_instructions}
                </div>
              </div>
              {activeProgress && (
                <div className="rounded-md border border-white/[0.08] bg-[#121614] p-3 text-xs text-zinc-200">
                  Progress: <strong>{activeProgress.status}</strong> · Epoch #
                  {activeProgress.reset_epoch} · Retest passed:{" "}
                  {String(activeProgress.retest_passed)}
                </div>
              )}
            </div>

            {canPractice && activeWorkspace && (
              <div className="space-y-5">
                <form
                  onSubmit={(e) => void handleValidateChallenge(e)}
                  className="space-y-3 rounded-lg border border-white/[0.068] bg-[#0e0e11] p-4"
                >
                  <h4 className="text-sm font-semibold text-white">
                    Non-Destructive Proof Validation
                  </h4>
                  <div className="grid gap-3 sm:grid-cols-2">
                    <label className="block text-xs text-zinc-300">
                      Target URL (Lab Only)
                      <input
                        value={targetUrl}
                        onChange={(e) => setTargetUrl(e.target.value)}
                        className="mt-1 w-full rounded-md border border-white/[0.1] bg-[#111114] px-3 py-1.5 text-xs font-mono text-white"
                        required
                      />
                    </label>
                    <label className="block text-xs text-zinc-300">
                      Safe Action Type
                      <Select
                        size="sm"
                        value={actionType}
                        onChange={(e) =>
                          setActionType(
                            e.target.value as (typeof SAFE_ACTIONS)[number],
                          )
                        }
                        className="mt-1"
                      >
                        {SAFE_ACTIONS.map((a) => (
                          <option key={a} value={a}>
                            {a}
                          </option>
                        ))}
                      </Select>
                    </label>
                  </div>
                  <div className="grid gap-3 sm:grid-cols-2">
                    <label className="block text-xs text-zinc-300">
                      Permitted Tool
                      <input
                        value={toolSlug}
                        onChange={(e) => setToolSlug(e.target.value)}
                        className="mt-1 vf-input font-mono text-xs"
                        required
                      />
                    </label>
                    <label className="block text-xs text-zinc-300">
                      Disposable Account
                      <Select
                        size="sm"
                        value={disposableIdentity}
                        onChange={(e) => setDisposableIdentity(e.target.value)}
                        className="mt-1"
                      >
                        {activeWorkspace.disposable_identities_json.map(
                          (ident) => (
                            <option key={ident.handle} value={ident.handle}>
                              {ident.handle}
                            </option>
                          ),
                        )}
                      </Select>
                    </label>
                  </div>
                  <label className="block text-xs text-zinc-300">
                    Observed Safe Evidence Summary
                    <textarea
                      rows={2}
                      value={observedEvidence}
                      onChange={(e) => setObservedEvidence(e.target.value)}
                      className="mt-1 w-full rounded-md border border-white/[0.1] bg-[#111114] px-3 py-1.5 text-xs text-white"
                    />
                  </label>
                  <button
                    type="submit"
                    disabled={busy}
                    className="vf-btn-primary px-3.5 py-1.5 text-xs font-medium"
                  >
                    Run Bounded Safe Validation
                  </button>
                </form>

                <form
                  onSubmit={(e) => void handleRecordRemediation(e)}
                  className="space-y-3 rounded-lg border border-white/[0.068] bg-[#0e0e11] p-4"
                >
                  <h4 className="text-sm font-semibold text-white">
                    Remediation & Retest Loop
                  </h4>
                  <textarea
                    rows={2}
                    placeholder="Describe code/config remediation applied before running remediation_retest..."
                    value={remediationNotes}
                    onChange={(e) => setRemediationNotes(e.target.value)}
                    className="w-full rounded-md border border-white/[0.1] bg-[#111114] px-3 py-1.5 text-xs text-white"
                    required
                  />
                  <button
                    type="submit"
                    disabled={busy}
                    className="vf-btn-secondary h-8 px-3.5 text-xs"
                  >
                    Save Remediation Exercise
                  </button>
                </form>
              </div>
            )}
          </div>
        )}
      </section>

      {/* VForge Self-Scans */}
      <section className="rounded-xl border border-white/[0.068] bg-[#141417] p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-lg font-medium text-white">
              VForge Control-Plane Self-Scan Verification
            </h2>
            <p className="text-xs text-zinc-400">
              Honest posture self-checks covering Compose security invariants and
              digest-pinned image lock files.
            </p>
          </div>
          {canManage && (
            <form
              onSubmit={(e) => void handleRunSelfScan(e)}
              className="flex flex-wrap items-center gap-2"
            >
              <div className="w-40">
                <Select
                  aria-label="Target VForge component"
                  size="sm"
                  value={selfScanComponent}
                  onChange={(e) =>
                    setSelfScanComponent(
                      e.target.value as (typeof SELF_SCAN_COMPONENTS)[number],
                    )
                  }
                >
                  {SELF_SCAN_COMPONENTS.map((comp) => (
                    <option key={comp} value={comp}>
                      {comp}
                    </option>
                  ))}
                </Select>
              </div>
              <input
                value={selfScanProfile}
                onChange={(e) => setSelfScanProfile(e.target.value)}
                className="rounded-md border border-white/[0.1] bg-[#0e0e11] px-3 py-1.5 text-xs text-white"
                required
              />
              <button
                type="submit"
                disabled={busy}
                className="vf-btn-primary px-3.5 py-1.5 text-xs font-medium"
              >
                Run Self-Scan
              </button>
            </form>
          )}
        </div>

        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-xs">
            <thead className="border-b border-white/[0.068] text-zinc-400">
              <tr>
                <th className="py-2 pr-4">Executed</th>
                <th className="py-2 pr-4">Component</th>
                <th className="py-2 pr-4">Checks</th>
                <th className="py-2 pr-4">Issues</th>
                <th className="py-2 pr-4">Regression Verified</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06] text-zinc-300">
              {(overview?.self_scans ?? []).map((s) => (
                <tr key={s.id}>
                  <td className="py-2 pr-4 font-mono">
                    {formatUtc(s.created_at)}
                  </td>
                  <td className="py-2 pr-4 font-mono text-white">
                    {s.target_component}
                  </td>
                  <td className="py-2 pr-4">{s.checks_executed}</td>
                  <td className="py-2 pr-4">{s.issues_found}</td>
                  <td className="py-2 pr-4">
                    {s.regression_verified ? "Pass" : "Fail"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Lab Audit Trail */}
      <section className="rounded-xl border border-white/[0.068] bg-[#141417] p-5">
        <h2 className="text-lg font-medium text-white">
          Append-Only Lab Audit Log
        </h2>
        <div className="mt-3 overflow-x-auto">
          <table className="min-w-full text-left text-xs">
            <thead className="border-b border-white/[0.068] text-zinc-400">
              <tr>
                <th className="py-2 pr-4">Occurred</th>
                <th className="py-2 pr-4">Action</th>
                <th className="py-2 pr-4">Actor</th>
                <th className="py-2 pr-4">Target</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06] text-zinc-300">
              {(overview?.audit_events ?? []).map((evt) => (
                <tr key={evt.id}>
                  <td className="py-2 pr-4 font-mono">
                    {formatUtc(evt.occurred_at)}
                  </td>
                  <td className="py-2 pr-4 font-medium text-white">
                    {evt.action}
                  </td>
                  <td className="py-2 pr-4">{evt.actor_email}</td>
                  <td className="py-2 pr-4 font-mono">
                    {evt.target_url || "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

export default function LearningLabPage() {
  const params = useParams<{ orgId: string }>();
  const orgId = params.orgId;
  return (
    <OrgShell orgId={orgId}>
      {({ auth, membership }) => (
        <LabContent
          orgId={orgId}
          membership={membership}
          csrfToken={auth.csrf_token ?? ""}
        />
      )}
    </OrgShell>
  );
}
