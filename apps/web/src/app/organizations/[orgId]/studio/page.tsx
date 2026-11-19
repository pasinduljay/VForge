"use client";

import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import OrgShell, { hasPermission } from "@/components/OrgShell";
import { Select } from "@/components/ui/Select";
import { apiFetch } from "@/lib/api";
import type {
  OrganizationMembershipSummary,
  RulePackItem,
  RulePackVersionItem,
  StudioOverview,
} from "@/lib/types";

function StudioContent({
  orgId,
  membership,
  csrfToken,
}: {
  orgId: string;
  membership: OrganizationMembershipSummary | null;
  csrfToken: string;
}) {
  const canAuthor = hasPermission(membership, "studio:author");
  const canReview = hasPermission(membership, "studio:review");
  const canPromote = hasPermission(membership, "studio:promote");

  const [overview, setOverview] = useState<StudioOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionMsg, setActionMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Create RulePack state
  const [packSlug, setPackSlug] = useState("vf-custom-appsec");
  const [packTitle, setPackTitle] = useState("Custom AppSec Detection Pack");
  const [packDesc, setPackDesc] = useState("Org-scoped signed detection rules.");

  // Author Candidate Rule Version / AI Draft Stub state
  const [selectedPackId, setSelectedPackId] = useState("");
  const [draftVersion, setDraftVersion] = useState("1.0.0");
  const [engine, setEngine] = useState<"opengrep" | "nuclei" | "checkov" | "gitleaks" | "zap" | "nmap">("opengrep");
  const [ruleKey, setRuleKey] = useState("vf-custom-eval-001");
  const [ruleTitle, setRuleTitle] = useState("Avoid unsafe dynamic eval");
  const [cweId, setCweId] = useState("CWE-95");

  const encodedOrgId = encodeURIComponent(orgId);

  const loadOverview = useCallback(async () => {
    try {
      const data = await apiFetch<StudioOverview>(
        `/api/v1/organizations/${encodedOrgId}/studio/overview`,
      );
      setOverview(data);
      setSelectedPackId((prev) => prev || (data.rule_packs[0]?.id ?? ""));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load Rule & Skill Studio");
    } finally {
      setLoading(false);
    }
  }, [encodedOrgId]);

  useEffect(() => {
    let active = true;
    void apiFetch<StudioOverview>(`/api/v1/organizations/${encodedOrgId}/studio/overview`)
      .then((data) => {
        if (!active) return;
        setOverview(data);
        setSelectedPackId((prev) => prev || (data.rule_packs[0]?.id ?? ""));
        setError(null);
        setLoading(false);
      })
      .catch((err) => {
        if (!active) return;
        setError(err instanceof Error ? err.message : "Failed to load Rule & Skill Studio");
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [encodedOrgId]);

  const handleCreatePack = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setActionMsg(null);
    setError(null);
    try {
      const pack = await apiFetch<RulePackItem>(
        `/api/v1/organizations/${encodedOrgId}/studio/rule-packs`,
        {
          method: "POST",
          csrfToken,
          body: JSON.stringify({
            slug: packSlug,
            title: packTitle,
            description: packDesc,
            owner_team: "security-engineering",
          }),
        },
      );
      setSelectedPackId(pack.id);
      setActionMsg(`Created rule pack '${pack.slug}'.`);
      await loadOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create rule pack");
    } finally {
      setBusy(false);
    }
  };

  const handleGenerateAiDraft = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedPackId) return;
    setBusy(true);
    setActionMsg(null);
    setError(null);
    try {
      const ver = await apiFetch<RulePackVersionItem>(
        `/api/v1/organizations/${encodedOrgId}/studio/rule-packs/${encodeURIComponent(selectedPackId)}/ai-draft`,
        {
          method: "POST",
          csrfToken,
          body: JSON.stringify({
            version: draftVersion,
            engine,
            rule_key: ruleKey,
            title: ruleTitle,
            cwe_id: cweId,
            target_context: "application_service",
            untrusted_source_snippet: "sample untrusted context snippet",
          }),
        },
      );
      setActionMsg(
        `Generated AI-assisted draft v${ver.version} (${ver.creation_method}). Must run fixtures and pass human peer review.`,
      );
      await loadOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to generate AI candidate draft");
    } finally {
      setBusy(false);
    }
  };

  const postVersionAction = async (path: string, bodyObj?: Record<string, unknown>, label?: string) => {
    setBusy(true);
    setActionMsg(null);
    setError(null);
    try {
      await apiFetch(`/api/v1/organizations/${encodedOrgId}/studio${path}`, {
        method: "POST",
        csrfToken,
        body: bodyObj ? JSON.stringify(bodyObj) : undefined,
      });
      setActionMsg(label || "Studio action completed.");
      await loadOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Studio action failed");
    } finally {
      setBusy(false);
    }
  };

  if (loading) {
    return <p className="text-sm text-zinc-400">Loading Rule &amp; Skill Studio...</p>;
  }

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Rule &amp; Skill Studio</h1>
          <p className="mt-1 text-sm text-zinc-400">
            Author native detection rules and constrained assessment skills, verify positive/negative/near-miss
            fixtures, enforce independent human review, Ed25519 sign, promote canary/stable, and roll back cleanly.
          </p>
        </div>
        <button
          type="button"
          onClick={() => void loadOverview()}
          className="vf-btn-secondary px-3 py-1.5 text-xs"
        >
          Refresh Studio
        </button>
      </div>

      {error && (
        <div className="rounded-md border border-white/[0.08] bg-[#131317] px-4 py-3 text-sm text-zinc-200">
          {error}
        </div>
      )}
      {actionMsg && (
        <div className="rounded-md border border-white/[0.08] bg-[#121614] px-4 py-3 text-sm text-zinc-200">
          {actionMsg}
        </div>
      )}

      {canAuthor && (
        <div className="grid gap-6 lg:grid-cols-2">
          <form
            onSubmit={handleCreatePack}
            className="space-y-4 rounded-xl border border-white/[0.068] bg-[#141417] p-5"
          >
            <h2 className="text-base font-semibold text-white">1. Create Rule Pack</h2>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="block text-xs text-zinc-300">
                Slug
                <input
                  value={packSlug}
                  onChange={(e) => setPackSlug(e.target.value)}
                  className="mt-1 vf-input"
                  required
                />
              </label>
              <label className="block text-xs text-zinc-300">
                Title
                <input
                  value={packTitle}
                  onChange={(e) => setPackTitle(e.target.value)}
                  className="mt-1 vf-input"
                  required
                />
              </label>
            </div>
            <label className="block text-xs text-zinc-300">
              Description
              <input
                value={packDesc}
                onChange={(e) => setPackDesc(e.target.value)}
                className="mt-1 vf-input"
              />
            </label>
            <button
              type="submit"
              disabled={busy}
              className="vf-btn-primary h-8 px-4 text-xs"
            >
              Create Rule Pack
            </button>
          </form>

          <form
            onSubmit={handleGenerateAiDraft}
            className="space-y-4 rounded-xl border border-white/[0.068] bg-[#141417] p-5"
          >
            <div className="flex items-center justify-between gap-2">
              <h2 className="text-base font-semibold text-white">2. AI Candidate Generator</h2>
              <span className="rounded bg-[#19191f] px-2 py-0.5 text-[11px] text-amber-300 border border-white/[0.08]">
                Phase 12 Gateway Stub — Requires Human Review
              </span>
            </div>
            <div className="grid gap-3 sm:grid-cols-3">
              <label className="block text-xs text-zinc-300">
                Rule Pack
                <Select
                  value={selectedPackId}
                  onChange={(e) => setSelectedPackId(e.target.value)}
                  required
                  className="mt-1"
                >
                  <option value="">Select pack...</option>
                  {(overview?.rule_packs || []).map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.slug}
                    </option>
                  ))}
                </Select>
              </label>
              <label className="block text-xs text-zinc-300">
                SemVer
                <input
                  value={draftVersion}
                  onChange={(e) => setDraftVersion(e.target.value)}
                  className="mt-1 vf-input"
                  required
                />
              </label>
              <label className="block text-xs text-zinc-300">
                Engine
                <Select
                  value={engine}
                  onChange={(e) =>
                    setEngine(
                      e.target.value as
                        | "opengrep"
                        | "nuclei"
                        | "checkov"
                        | "gitleaks"
                        | "zap"
                        | "nmap",
                    )
                  }
                  className="mt-1"
                >
                  {(overview?.supported_engines || []).map((eng) => (
                    <option key={eng} value={eng}>
                      {eng}
                    </option>
                  ))}
                </Select>
              </label>
            </div>
            <div className="grid gap-3 sm:grid-cols-3">
              <label className="block text-xs text-zinc-300">
                Rule Key
                <input
                  value={ruleKey}
                  onChange={(e) => setRuleKey(e.target.value)}
                  className="mt-1 vf-input"
                  required
                />
              </label>
              <label className="block text-xs text-zinc-300">
                CWE ID
                <input
                  value={cweId}
                  onChange={(e) => setCweId(e.target.value)}
                  className="mt-1 vf-input"
                  required
                />
              </label>
              <label className="block text-xs text-zinc-300">
                Rule Title
                <input
                  value={ruleTitle}
                  onChange={(e) => setRuleTitle(e.target.value)}
                  className="mt-1 vf-input"
                  required
                />
              </label>
            </div>
            <button
              type="submit"
              disabled={busy || !selectedPackId}
              className="vf-btn-primary h-8 px-4 text-xs"
            >
              Generate AI Draft (Untrusted Input Isolated)
            </button>
          </form>
        </div>
      )}

      {/* Rule Packs & Versions */}
      <section className="space-y-4">
        <h2 className="text-lg font-semibold text-white">Rule Packs &amp; Lifecycle Channels</h2>
        {(overview?.rule_packs || []).length === 0 ? (
          <div className="rounded-xl border border-white/[0.068] bg-[#141417]/90 p-6 text-sm text-zinc-400">
            No custom rule packs registered for this organization yet.
          </div>
        ) : (
          (overview?.rule_packs || []).map((pack) => (
            <div key={pack.id} className="rounded-xl border border-white/[0.068] bg-[#141417] p-5 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h3 className="text-base font-semibold text-white">
                    {pack.title} <span className="text-xs font-mono text-zinc-400">({pack.slug})</span>
                  </h3>
                  <p className="text-xs text-zinc-400">{pack.description}</p>
                </div>
                {canPromote && (
                  <div className="flex gap-2">
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() =>
                        void postVersionAction(
                          `/rule-packs/${encodeURIComponent(pack.id)}/rollback`,
                          { target_channel: "canary", reason: "Operator canary rollback", quarantine: false },
                          `Rolled back canary for ${pack.slug}`,
                        )
                      }
                      className="vf-btn-warning px-2.5 py-1 text-xs"
                    >
                      Rollback Canary
                    </button>
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() =>
                        void postVersionAction(
                          `/rule-packs/${encodeURIComponent(pack.id)}/rollback`,
                          { target_channel: "stable", reason: "Operator stable rollback", quarantine: true },
                          `Quarantined & rolled back stable for ${pack.slug}`,
                        )
                      }
                      className="vf-btn-danger px-2.5 py-1 text-xs"
                    >
                      Rollback &amp; Quarantine Stable
                    </button>
                  </div>
                )}
              </div>

              <div className="space-y-3">
                {pack.versions.map((ver) => (
                  <div
                    key={ver.id}
                    className="rounded-lg border border-white/[0.068] bg-[#0e0e11]/70 p-4 space-y-3"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex flex-wrap items-center gap-2 text-xs">
                        <span className="font-mono font-semibold text-white">v{ver.version}</span>
                        <span className="rounded bg-[#1c1c20] px-2 py-0.5 text-zinc-300">
                          channel: {ver.channel}
                        </span>
                        <span className="rounded bg-[#1c1c20] px-2 py-0.5 text-zinc-300">
                          review: {ver.review_status}
                        </span>
                        <span className="rounded bg-[#1c1c20] px-2 py-0.5 text-zinc-300">
                          origin: {ver.creation_method} ({ver.author_actor_type})
                        </span>
                        {ver.signed_at && (
                          <span className="rounded bg-[#1a1a1f] border border-white/[0.08] px-2 py-0.5 text-zinc-200">
                            Ed25519 Signed
                          </span>
                        )}
                      </div>
                      <div className="text-xs text-zinc-400">
                        TP: {ver.true_positive_count} · FP: {ver.false_positive_count} · FN:{" "}
                        {ver.false_negative_count} · Fixtures:{" "}
                        <span
                          className={
                            ver.fixture_regression_passed ? "text-zinc-200" : "text-amber-300"
                          }
                        >
                          {ver.fixture_regression_passed ? "PASSED" : "PENDING/FAILED"}
                        </span>
                      </div>
                    </div>

                    {ver.rules.length > 0 && (
                      <div className="space-y-2">
                        {ver.rules.map((rule) => (
                          <div
                            key={rule.id}
                            className="rounded border border-white/[0.08] bg-[#141417] p-2.5 text-xs space-y-1"
                          >
                            <div className="flex flex-wrap items-center justify-between gap-2 text-zinc-300">
                              <span className="font-mono font-medium text-white">
                                {rule.rule_key} ({rule.engine})
                              </span>
                              <span className="text-zinc-400">
                                {rule.cwe_id ?? "No CWE"} · severity: {rule.severity}
                              </span>
                            </div>
                            <p className="text-zinc-400">
                              Known limitations: {rule.known_limitations}
                            </p>
                            <pre className="max-h-36 overflow-auto rounded bg-[#101013] p-2 font-mono text-[11px] text-zinc-300">
                              {rule.native_content}
                            </pre>
                          </div>
                        ))}
                      </div>
                    )}

                    <div className="flex flex-wrap gap-2">
                      {canAuthor && !ver.signed_at && (
                        <>
                          <button
                            type="button"
                            disabled={busy}
                            onClick={() =>
                              void postVersionAction(
                                `/rule-pack-versions/${encodeURIComponent(ver.id)}/run-fixtures`,
                                undefined,
                                `Executed fixture corpus for v${ver.version}`,
                              )
                            }
                            className="rounded bg-[#1c1c20] px-2.5 py-1 text-xs text-zinc-200 hover:bg-zinc-700"
                          >
                            Run Fixtures (Pos/Neg/Near-Miss)
                          </button>
                          <button
                            type="button"
                            disabled={
                              busy ||
                              !ver.fixture_regression_passed ||
                              ver.review_status === "pending_review" ||
                              ver.review_status === "approved"
                            }
                            onClick={() =>
                              void postVersionAction(
                                `/rule-pack-versions/${encodeURIComponent(ver.id)}/submit-review`,
                                undefined,
                                `Submitted v${ver.version} for peer review`,
                              )
                            }
                            className="rounded bg-[#1c1c20] px-2.5 py-1 text-xs text-zinc-200 hover:bg-zinc-700 disabled:opacity-40"
                          >
                            Submit Review
                          </button>
                        </>
                      )}
                      {canReview && !ver.signed_at && (
                        <>
                          <button
                            type="button"
                            disabled={
                              busy ||
                              !ver.fixture_regression_passed ||
                              ver.review_status !== "pending_review"
                            }
                            onClick={() =>
                              void postVersionAction(
                                `/rule-pack-versions/${encodeURIComponent(ver.id)}/review`,
                                { decision: "approved", comment: "Verified fixtures & limitations" },
                                `Approved v${ver.version}`,
                              )
                            }
                            className="vf-btn-primary px-3 py-1 text-xs"
                          >
                            Peer Approve
                          </button>
                          <button
                            type="button"
                            disabled={busy || ver.review_status !== "pending_review"}
                            onClick={() =>
                              void postVersionAction(
                                `/rule-pack-versions/${encodeURIComponent(ver.id)}/review`,
                                { decision: "rejected", comment: "Rejected during peer review" },
                                `Rejected v${ver.version}`,
                              )
                            }
                            className="vf-btn-danger h-7 px-3 text-xs"
                          >
                            Reject
                          </button>
                        </>
                      )}
                      {canPromote && !ver.signed_at && ver.review_status === "approved" && (
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() =>
                            void postVersionAction(
                              `/rule-pack-versions/${encodeURIComponent(ver.id)}/sign`,
                              undefined,
                              `Signed immutable manifest for v${ver.version}`,
                            )
                          }
                          className="vf-btn-primary px-2.5 py-1 text-xs"
                        >
                          Ed25519 Sign
                        </button>
                      )}
                      {canPromote && ver.signed_at && (
                        <>
                          <button
                            type="button"
                            disabled={busy || ver.channel === "quarantined"}
                            onClick={() =>
                              void postVersionAction(
                                `/rule-pack-versions/${encodeURIComponent(ver.id)}/promote`,
                                { target_channel: "canary" },
                                `Promoted v${ver.version} to Canary`,
                              )
                            }
                            className="vf-btn-warning h-7 px-3 text-xs"
                          >
                            Promote Canary
                          </button>
                          <button
                            type="button"
                            disabled={busy || ver.channel === "quarantined"}
                            onClick={() =>
                              void postVersionAction(
                                `/rule-pack-versions/${encodeURIComponent(ver.id)}/promote`,
                                { target_channel: "stable" },
                                `Promoted v${ver.version} to Stable`,
                              )
                            }
                            className="vf-btn-primary px-3 py-1 text-xs"
                          >
                            Promote Stable
                          </button>
                        </>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))
        )}
      </section>

      {/* Assessment Skills Summary */}
      <section className="space-y-3">
        <h2 className="text-lg font-semibold text-white">Constrained AI Assessment Skills</h2>
        {(overview?.skills || []).length === 0 ? (
          <div className="rounded-xl border border-white/[0.068] bg-[#141417]/90 p-5 text-sm text-zinc-400">
            No bounded assessment skills registered yet.
          </div>
        ) : (
          <div className="grid gap-4 md:grid-cols-2">
            {(overview?.skills || []).map((skill) => (
              <div key={skill.id} className="rounded-xl border border-white/[0.068] bg-[#141417] p-4 space-y-2">
                <div className="text-sm font-semibold text-white">
                  {skill.title} <span className="font-mono text-xs text-zinc-400">({skill.slug})</span>
                </div>
                <p className="text-xs text-zinc-400">{skill.description}</p>
                {skill.versions.map((sv) => (
                  <div key={sv.id} className="rounded border border-white/[0.068] bg-[#0e0e11]/70 p-2.5 text-xs text-zinc-300">
                    v{sv.version} · {sv.channel} · {sv.review_status} · caps:{" "}
                    {sv.allowed_capabilities.join(", ")}
                  </div>
                ))}
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Immutable Audit Events */}
      <section className="space-y-3">
        <h2 className="text-lg font-semibold text-white">Studio Audit Trail</h2>
        <div className="overflow-x-auto rounded-xl border border-white/[0.08]">
          <table className="min-w-full divide-y divide-white/[0.06] text-left text-xs">
            <thead className="bg-[#141417] text-zinc-400">
              <tr>
                <th className="px-4 py-2">When</th>
                <th className="px-4 py-2">Entity</th>
                <th className="px-4 py-2">Action</th>
                <th className="px-4 py-2">Actor</th>
                <th className="px-4 py-2">Transition</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06] bg-[#101013] text-zinc-300">
              {(overview?.audit_events || []).map((ev) => (
                <tr key={ev.id}>
                  <td className="px-4 py-2 font-mono">{new Date(ev.occurred_at).toLocaleString()}</td>
                  <td className="px-4 py-2">{ev.entity_type}</td>
                  <td className="px-4 py-2 font-medium text-white">{ev.action}</td>
                  <td className="px-4 py-2">
                    {ev.actor_email} ({ev.actor_type})
                  </td>
                  <td className="px-4 py-2">
                    {ev.previous_state ? `${ev.previous_state} -> ` : ""}
                    {ev.new_state || "-"}
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

export default function OrganizationStudioPage() {
  const params = useParams<{ orgId: string }>();
  const orgId = params.orgId;

  return (
    <OrgShell orgId={orgId}>
      {({ auth, membership }) => (
        <StudioContent
          orgId={orgId}
          membership={membership}
          csrfToken={auth.csrf_token ?? ""}
        />
      )}
    </OrgShell>
  );
}
