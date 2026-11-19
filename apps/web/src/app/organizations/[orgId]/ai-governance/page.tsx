"use client";

import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import OrgShell, { hasPermission } from "@/components/OrgShell";
import { Select } from "@/components/ui/Select";
import { apiFetch, formatUtc } from "@/lib/api";
import type {
  AiGovernanceOverview,
  AiTaskExecuteResult,
  KnowledgeSearchHitItem,
  OrganizationMembershipSummary,
} from "@/lib/types";

const AGENT_ROLES = [
  "architect",
  "attack_surface_analyst",
  "rule_author",
  "adversarial_reviewer",
  "evidence_verifier",
  "remediation_reviewer",
  "independent_critic",
] as const;

const PROVIDER_CLASSES = [
  "local_inference",
  "managed_zdr",
  "managed_retained",
  "openai",
  "openai_compatible",
] as const;

const KNOWLEDGE_TYPES = [
  "owasp_asvs",
  "cwe_catalog",
  "internal_runbook",
  "remediation_guide",
  "approved_framework",
] as const;

function AiGovernanceContent({
  orgId,
  membership,
  csrfToken,
}: {
  orgId: string;
  membership: OrganizationMembershipSummary | null;
  csrfToken: string;
}) {
  const canRead = hasPermission(membership, "ai:read");
  const canInvoke = hasPermission(membership, "ai:invoke");
  const canManage = hasPermission(membership, "ai:manage");

  const [overview, setOverview] = useState<AiGovernanceOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionMsg, setActionMsg] = useState<string | null>(null);

  // Provider configuration state
  const [providerClass, setProviderClass] =
    useState<(typeof PROVIDER_CLASSES)[number]>("local_inference");
  const [providerName, setProviderName] = useState("Local Qwen3 Gateway");
  const [endpointUrl, setEndpointUrl] = useState("");
  const [secretRef, setSecretRef] = useState("");
  const [allowedModelsInput, setAllowedModelsInput] = useState("ollama/qwen3-coder");
  const [localOnlyMode, setLocalOnlyMode] = useState(false);
  const [monthlyBudgetUsd, setMonthlyBudgetUsd] = useState("25");
  const [maxTokensLimit, setMaxTokensLimit] = useState("8192");

  // AI task execution state
  const [roleName, setRoleName] =
    useState<(typeof AGENT_ROLES)[number]>("remediation_reviewer");
  const [taskType, setTaskType] = useState("remediation_draft");
  const [modelSlug, setModelSlug] = useState("ollama/qwen3-coder");
  const [selectedProviderId, setSelectedProviderId] = useState("");
  const [rawPrompt, setRawPrompt] = useState(
    "Provide a concise parameterized-query remediation note for CWE-89 SQL injection.",
  );
  const [ragQuery, setRagQuery] = useState("parameterized SQL");
  const [proposedAction, setProposedAction] = useState("finding:suggest_remediation");
  const [consentAcknowledged, setConsentAcknowledged] = useState(false);
  const [requireLocalOnly, setRequireLocalOnly] = useState(false);
  const [lastTaskResult, setLastTaskResult] = useState<AiTaskExecuteResult | null>(null);

  // Knowledge base state
  const [docSlug, setDocSlug] = useState("owasp-asvs-sql-param");
  const [docTitle, setDocTitle] = useState("OWASP ASVS SQL Parameterization");
  const [docType, setDocType] =
    useState<(typeof KNOWLEDGE_TYPES)[number]>("owasp_asvs");
  const [docUri, setDocUri] = useState("curated://owasp/asvs-v5.3");
  const [docContent, setDocContent] = useState(
    "Always enforce strict allowlist validation and parameterized SQL statements cleanly.",
  );
  const [searchQuery, setSearchQuery] = useState("");
  const [searchHits, setSearchHits] = useState<KnowledgeSearchHitItem[]>([]);

  // Feedback & Evaluation state
  const [evalModelSlug, setEvalModelSlug] = useState("ollama/qwen3-coder");
  const [evalSuiteName, setEvalSuiteName] = useState("appsec-benchmark-v1");
  const [evalSamples, setEvalSamples] = useState("40");
  const [evalTpr, setEvalTpr] = useState("0.92");
  const [evalFpr, setEvalFpr] = useState("0.04");

  const encodedOrgId = encodeURIComponent(orgId);

  const loadOverview = useCallback(async () => {
    try {
      const data = await apiFetch<AiGovernanceOverview>(
        `/api/v1/organizations/${encodedOrgId}/ai/overview`,
      );
      setOverview(data);
      setSelectedProviderId((prev) => prev || (data.provider_configs[0]?.id ?? ""));
      setError(null);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to load AI Governance workspace",
      );
    } finally {
      setLoading(false);
    }
  }, [encodedOrgId]);

  useEffect(() => {
    let active = true;
    void apiFetch<AiGovernanceOverview>(
      `/api/v1/organizations/${encodedOrgId}/ai/overview`,
    )
      .then((data) => {
        if (!active) return;
        setOverview(data);
        setSelectedProviderId((prev) => prev || (data.provider_configs[0]?.id ?? ""));
        setError(null);
        setLoading(false);
      })
      .catch((err) => {
        if (!active) return;
        setError(
          err instanceof Error ? err.message : "Failed to load AI Governance workspace",
        );
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [encodedOrgId]);

  const parseNum = (value: string, fallback: number): number => {
    const trimmed = value.trim();
    if (!trimmed) return fallback;
    const parsed = Number(trimmed);
    return Number.isFinite(parsed) ? parsed : fallback;
  };

  const handleConfigureProvider = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setActionMsg(null);
    try {
      const parsedModels = allowedModelsInput
        .split(",")
        .map((m) => m.trim())
        .filter(Boolean);
      const created = await apiFetch<{ id: string; display_name: string }>(
        `/api/v1/organizations/${encodedOrgId}/ai/providers`,
        {
          method: "POST",
          csrfToken,
          body: JSON.stringify({
            provider_class: providerClass,
            display_name: providerName,
            endpoint_url: endpointUrl.trim() || null,
            secret_ref: secretRef.trim() || null,
            local_only_mode: localOnlyMode,
            allowed_models: parsedModels,
            monthly_budget_usd: parseNum(monthlyBudgetUsd, 25),
            max_tokens_per_request: parseNum(maxTokensLimit, 8192),
          }),
        },
      );
      setSelectedProviderId(created.id);
      setActionMsg(`Configured AI provider "${created.display_name}".`);
      await loadOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to configure AI provider");
    } finally {
      setBusy(false);
    }
  };

  const handleToggleConsent = async (
    providerId: string,
    approved: boolean,
    localOnly?: boolean,
  ) => {
    setBusy(true);
    setError(null);
    setActionMsg(null);
    try {
      await apiFetch(
        `/api/v1/organizations/${encodedOrgId}/ai/providers/${encodeURIComponent(providerId)}/consent`,
        {
          method: "POST",
          csrfToken,
          body: JSON.stringify({
            approved,
            local_only_mode: localOnly ?? null,
          }),
        },
      );
      setActionMsg("Updated provider governance policy.");
      await loadOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update provider policy");
    } finally {
      setBusy(false);
    }
  };

  const handleExecuteTask = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProviderId) {
      setError("Select or configure at least one AI provider connector first.");
      return;
    }
    setBusy(true);
    setError(null);
    setActionMsg(null);
    try {
      const result = await apiFetch<AiTaskExecuteResult>(
        `/api/v1/organizations/${encodedOrgId}/ai/tasks/execute`,
        {
          method: "POST",
          csrfToken,
          body: JSON.stringify({
            task_type: taskType,
            role_name: roleName,
            raw_prompt: rawPrompt,
            model_slug: modelSlug,
            provider_config_ids: [selectedProviderId],
            consent_acknowledged: consentAcknowledged,
            require_local_only: requireLocalOnly,
            rag_query: ragQuery.trim() || null,
            proposed_tools: proposedAction.trim()
              ? [
                  {
                    tool_action: proposedAction.trim(),
                    target_resource_type: "finding",
                    target_resource_id: "00000000-0000-0000-0000-000000000001",
                    arguments_json: { source: "ai-governance-ui" },
                  },
                ]
              : [],
          }),
        },
      );
      setLastTaskResult(result);
      setActionMsg(
        `AI run ${result.run.id.slice(0, 8)} completed (${result.task_request.data_classification}).`,
      );
      await loadOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : "AI task blocked or failed");
    } finally {
      setBusy(false);
    }
  };

  const handleDecideProposal = async (
    proposalId: string,
    decision: "approved" | "rejected",
  ) => {
    setBusy(true);
    setError(null);
    setActionMsg(null);
    try {
      await apiFetch(
        `/api/v1/organizations/${encodedOrgId}/ai/tool-proposals/${encodeURIComponent(proposalId)}/decide`,
        {
          method: "POST",
          csrfToken,
          body: JSON.stringify({
            decision,
            comment: `Operator ${decision} from AI Governance console`,
          }),
        },
      );
      setActionMsg(`Tool proposal ${decision}.`);
      await loadOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to record tool decision");
    } finally {
      setBusy(false);
    }
  };

  const handleIndexKnowledge = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setActionMsg(null);
    try {
      await apiFetch(
        `/api/v1/organizations/${encodedOrgId}/ai/knowledge/documents`,
        {
          method: "POST",
          csrfToken,
          body: JSON.stringify({
            slug: docSlug,
            title: docTitle,
            source_type: docType,
            source_uri: docUri,
            content: docContent,
          }),
        },
      );
      setActionMsg(`Indexed curated RAG document "${docSlug}".`);
      await loadOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to index document");
    } finally {
      setBusy(false);
    }
  };

  const handleSearchKnowledge = async (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim().length < 2) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const hits = await apiFetch<KnowledgeSearchHitItem[]>(
        `/api/v1/organizations/${encodedOrgId}/ai/knowledge/search?q=${encodeURIComponent(searchQuery)}`,
      );
      setSearchHits(hits);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Knowledge search failed");
    } finally {
      setBusy(false);
    }
  };

  const handleRecordEval = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setActionMsg(null);
    try {
      await apiFetch(
        `/api/v1/organizations/${encodedOrgId}/ai/evaluations`,
        {
          method: "POST",
          csrfToken,
          body: JSON.stringify({
            model_slug: evalModelSlug,
            suite_name: evalSuiteName,
            sample_count: parseNum(evalSamples, 10),
            true_positive_rate: parseNum(evalTpr, 0.9),
            false_positive_rate: parseNum(evalFpr, 0.05),
          }),
        },
      );
      setActionMsg("Recorded model evaluation run.");
      await loadOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Evaluation failed");
    } finally {
      setBusy(false);
    }
  };

  if (!canRead) {
    return (
      <div className="rounded-lg border border-white/[0.08] bg-[#131317] p-6 text-sm text-zinc-200">
        Your role does not grant access to AI Governance controls (`ai:read`).
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-white">
            AI Provider Governance &amp; Multi-Agent Control
          </h1>
          <p className="mt-1 text-sm text-zinc-300">
            Provider-agnostic AI gateway with pre-egress secret/PII redaction, prompt-injection
            quarantine, 30-day retention consent gates, fail-closed OPA tool broker, and
            tenant-isolated RAG memory.
          </p>
        </div>
        <button
          type="button"
          onClick={() => void loadOverview()}
          disabled={loading || busy}
          className="vf-btn-secondary h-8 px-3.5 text-xs"
        >
          Refresh
        </button>
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

      {/* Model Catalog */}
      <section className="rounded-xl border border-white/[0.068] bg-[#141417] p-5">
        <h2 className="text-lg font-medium text-white">Controlled Model Catalog</h2>
        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-white/[0.068] text-xs uppercase text-zinc-400">
                <th className="py-2 pr-4">Model</th>
                <th className="py-2 pr-4">Provider</th>
                <th className="py-2 pr-4">Execution</th>
                <th className="py-2 pr-4">Retention &amp; ZDR</th>
                <th className="py-2 pr-4">Capabilities</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06]">
              {(overview?.model_catalog ?? []).map((item) => (
                <tr key={item.id}>
                  <td className="py-2.5 pr-4 font-mono text-xs text-zinc-200">
                    {item.model_slug}
                  </td>
                  <td className="py-2.5 pr-4 text-zinc-300">{item.provider_class}</td>
                  <td className="py-2.5 pr-4">
                    <span
                      className={`rounded px-2 py-0.5 text-xs ${
                        item.is_local
                          ? "bg-[#1a1a1f] text-zinc-200"
                          : "bg-[#1a1a1f] text-[#93c5fd]"
                      }`}
                    >
                      {item.is_local ? "Local-Only" : "External API"}
                    </span>
                  </td>
                  <td className="py-2.5 pr-4">
                    {item.requires_retention_consent ? (
                      <span className="rounded bg-[#19191f] px-2 py-0.5 text-xs text-amber-300">
                        {item.retention_days}d Retention / No ZDR / Consent Required
                      </span>
                    ) : (
                      <span className="text-xs text-zinc-300">
                        {item.zdr_available ? "Zero Retention (ZDR)" : `${item.retention_days}d`}
                      </span>
                    )}
                  </td>
                  <td className="py-2.5 pr-4 text-xs text-zinc-400">
                    {item.capabilities_json.join(", ")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Provider Configuration & Existing Providers */}
      <div className="grid gap-6 lg:grid-cols-2">
        <section className="rounded-xl border border-white/[0.068] bg-[#141417] p-5">
          <h2 className="text-lg font-medium text-white">Tenant AI Provider Connectors</h2>
          <div className="mt-4 space-y-3">
            {(overview?.provider_configs ?? []).map((cfg) => (
              <div
                key={cfg.id}
                className="rounded-lg border border-white/[0.068] bg-[#0e0e11]/70 p-4 text-sm"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <div className="font-medium text-white">{cfg.display_name}</div>
                    <div className="text-xs text-zinc-400">
                      {cfg.provider_class} · Secret Ref:{" "}
                      <span className="font-mono">{cfg.secret_ref || "none"}</span> · Budget: $
                      {cfg.monthly_budget_usd}/mo
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <span
                      className={`rounded px-2 py-0.5 text-xs ${
                        cfg.local_only_mode
                          ? "bg-[#1a1a1f] text-zinc-200"
                          : "bg-[#1c1c20] text-zinc-300"
                      }`}
                    >
                      {cfg.local_only_mode ? "Local-Only Enforced" : "Standard Egress"}
                    </span>
                    <span
                      className={`rounded px-2 py-0.5 text-xs ${
                        cfg.retention_consent_approved
                          ? "bg-[#19191f] text-amber-300"
                          : "bg-[#1c1c20] text-zinc-400"
                      }`}
                    >
                      {cfg.retention_consent_approved
                        ? "Retention Consent Approved"
                        : "Consent Off"}
                    </span>
                  </div>
                </div>
                {canManage && (
                  <div className="mt-3 flex flex-wrap gap-2">
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() =>
                        void handleToggleConsent(
                          cfg.id,
                          !cfg.retention_consent_approved,
                          cfg.local_only_mode,
                        )
                      }
                      className="vf-btn-secondary px-2.5 py-1 text-xs"
                    >
                      {cfg.retention_consent_approved
                        ? "Revoke Retention Consent"
                        : "Approve Retention Consent"}
                    </button>
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() =>
                        void handleToggleConsent(
                          cfg.id,
                          cfg.retention_consent_approved,
                          !cfg.local_only_mode,
                        )
                      }
                      className="vf-btn-secondary px-2.5 py-1 text-xs"
                    >
                      {cfg.local_only_mode ? "Disable Local-Only" : "Enforce Local-Only"}
                    </button>
                  </div>
                )}
              </div>
            ))}
            {overview && overview.provider_configs.length === 0 && (
              <p className="text-sm text-zinc-400">
                No AI providers configured yet for this organization.
              </p>
            )}
          </div>
        </section>

        {canManage && (
          <section className="rounded-xl border border-white/[0.068] bg-[#141417] p-5">
            <h2 className="text-lg font-medium text-white">Add Provider Connector</h2>
            <p className="mt-1 text-xs text-zinc-400">
              Stores secret-manager reference names only; raw API keys and private external
              endpoints are rejected.
            </p>
            <form onSubmit={handleConfigureProvider} className="mt-4 space-y-3 text-sm">
              <div className="grid gap-3 sm:grid-cols-2">
                <label className="block">
                  <span className="text-xs text-zinc-300">Provider Class</span>
                  <Select
                    value={providerClass}
                    onChange={(e) =>
                      setProviderClass(e.target.value as (typeof PROVIDER_CLASSES)[number])
                    }
                    className="mt-1"
                  >
                    {PROVIDER_CLASSES.map((c) => (
                      <option key={c} value={c}>
                        {c}
                      </option>
                    ))}
                  </Select>
                </label>
                <label className="block">
                  <span className="text-xs text-zinc-300">Display Name</span>
                  <input
                    value={providerName}
                    onChange={(e) => setProviderName(e.target.value)}
                    required
                    className="mt-1 w-full rounded border border-white/[0.1] bg-[#0e0e11] px-3 py-1.5 text-zinc-100"
                  />
                </label>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <label className="block">
                  <span className="text-xs text-zinc-300">Secret Reference Name</span>
                  <input
                    value={secretRef}
                    onChange={(e) => setSecretRef(e.target.value)}
                    placeholder="e.g. VF_AI_ORG_KEY_REF"
                    className="mt-1 w-full rounded border border-white/[0.1] bg-[#0e0e11] px-3 py-1.5 text-zinc-100"
                  />
                </label>
                <label className="block">
                  <span className="text-xs text-zinc-300">Endpoint URL (optional)</span>
                  <input
                    value={endpointUrl}
                    onChange={(e) => setEndpointUrl(e.target.value)}
                    placeholder="https://..."
                    className="mt-1 w-full rounded border border-white/[0.1] bg-[#0e0e11] px-3 py-1.5 text-zinc-100"
                  />
                </label>
              </div>
              <div className="grid gap-3 sm:grid-cols-3">
                <label className="block sm:col-span-1">
                  <span className="text-xs text-zinc-300">Monthly Budget (USD)</span>
                  <input
                    type="number"
                    step="0.5"
                    value={monthlyBudgetUsd}
                    onChange={(e) => setMonthlyBudgetUsd(e.target.value)}
                    className="mt-1 w-full rounded border border-white/[0.1] bg-[#0e0e11] px-3 py-1.5 text-zinc-100"
                  />
                </label>
                <label className="block sm:col-span-1">
                  <span className="text-xs text-zinc-300">Max Tokens</span>
                  <input
                    type="number"
                    value={maxTokensLimit}
                    onChange={(e) => setMaxTokensLimit(e.target.value)}
                    className="mt-1 w-full rounded border border-white/[0.1] bg-[#0e0e11] px-3 py-1.5 text-zinc-100"
                  />
                </label>
                <label className="block sm:col-span-1">
                  <span className="text-xs text-zinc-300">Allowed Models</span>
                  <input
                    value={allowedModelsInput}
                    onChange={(e) => setAllowedModelsInput(e.target.value)}
                    className="mt-1 w-full rounded border border-white/[0.1] bg-[#0e0e11] px-3 py-1.5 text-zinc-100"
                  />
                </label>
              </div>
              <label className="flex items-center gap-2 text-xs text-zinc-300">
                <input
                  type="checkbox"
                  checked={localOnlyMode}
                  onChange={(e) => setLocalOnlyMode(e.target.checked)}
                />
                Enforce Local-Only Mode (blocks all external non-local models for this tenant)
              </label>
              <button
                type="submit"
                disabled={busy}
                className="vf-btn-primary h-8 px-4 text-xs"
              >
                Save Provider Config
              </button>
            </form>
          </section>
        )}
      </div>

      {/* Multi-Agent Task Execution + OPA Tool Broker */}
      <div className="grid gap-6 lg:grid-cols-2">
        {canInvoke && (
          <section className="rounded-xl border border-white/[0.068] bg-[#141417] p-5">
            <h2 className="text-lg font-medium text-white">Execute Governed Multi-Agent Task</h2>
            <form onSubmit={handleExecuteTask} className="mt-4 space-y-3 text-sm">
              <div className="grid gap-3 sm:grid-cols-2">
                <label className="block">
                  <span className="text-xs text-zinc-300">Agent Role</span>
                  <Select
                    value={roleName}
                    onChange={(e) =>
                      setRoleName(e.target.value as (typeof AGENT_ROLES)[number])
                    }
                    className="mt-1"
                  >
                    {AGENT_ROLES.map((r) => (
                      <option key={r} value={r}>
                        {r}
                      </option>
                    ))}
                  </Select>
                </label>
                <label className="block">
                  <span className="text-xs text-zinc-300">Task Type</span>
                  <input
                    value={taskType}
                    onChange={(e) => setTaskType(e.target.value)}
                    required
                    className="mt-1 vf-input"
                  />
                </label>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <label className="block">
                  <span className="text-xs text-zinc-300">Provider Config</span>
                  <Select
                    value={selectedProviderId}
                    onChange={(e) => setSelectedProviderId(e.target.value)}
                    className="mt-1"
                  >
                    <option value="">-- Choose Provider --</option>
                    {(overview?.provider_configs ?? []).map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.display_name} ({p.provider_class})
                      </option>
                    ))}
                  </Select>
                </label>
                <label className="block">
                  <span className="text-xs text-zinc-300">Model Slug</span>
                  <Select
                    value={modelSlug}
                    onChange={(e) => setModelSlug(e.target.value)}
                    className="mt-1"
                  >
                    {(overview?.model_catalog ?? []).map((m) => (
                      <option key={m.id} value={m.model_slug}>
                        {m.model_slug} ({m.is_local ? "local" : "external"})
                      </option>
                    ))}
                  </Select>
                </label>
              </div>
              <label className="block">
                <span className="text-xs text-zinc-300">
                  Prompt Input (secrets/PII automatically redacted pre-egress)
                </span>
                <textarea
                  rows={3}
                  value={rawPrompt}
                  onChange={(e) => setRawPrompt(e.target.value)}
                  required
                  className="mt-1 w-full rounded border border-white/[0.1] bg-[#0e0e11] px-3 py-2 text-zinc-100"
                />
              </label>
              <div className="grid gap-3 sm:grid-cols-2">
                <label className="block">
                  <span className="text-xs text-zinc-300">RAG Context Query</span>
                  <input
                    value={ragQuery}
                    onChange={(e) => setRagQuery(e.target.value)}
                    className="mt-1 w-full rounded border border-white/[0.1] bg-[#0e0e11] px-3 py-1.5 text-zinc-100"
                  />
                </label>
                <label className="block">
                  <span className="text-xs text-zinc-300">Proposed Tool Action (OPA-Gated)</span>
                  <input
                    value={proposedAction}
                    onChange={(e) => setProposedAction(e.target.value)}
                    placeholder="e.g. remediation:propose"
                    className="mt-1 w-full rounded border border-white/[0.1] bg-[#0e0e11] px-3 py-1.5 text-zinc-100"
                  />
                </label>
              </div>
              <div className="flex flex-wrap gap-4 text-xs text-zinc-300">
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={consentAcknowledged}
                    onChange={(e) => setConsentAcknowledged(e.target.checked)}
                  />
                  Acknowledge Retention Consent (for 30d non-ZDR models)
                </label>
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={requireLocalOnly}
                    onChange={(e) => setRequireLocalOnly(e.target.checked)}
                  />
                  Require Local-Only Execution
                </label>
              </div>
              <button
                type="submit"
                disabled={busy}
                className="vf-btn-primary h-8 px-4 text-xs"
              >
                Run Governed AI Task
              </button>
            </form>

            {lastTaskResult && (
              <div className="mt-4 rounded-lg border border-white/[0.068] bg-[#0e0e11]/80 p-4 text-xs">
                <div className="flex flex-wrap items-center gap-2 text-zinc-200">
                  <span className="font-semibold">Latest Run:</span>
                  <span className="font-mono">{lastTaskResult.run.model_slug}</span>
                  <span className="rounded bg-[#1c1c20] px-2 py-0.5">
                    {lastTaskResult.task_request.data_classification}
                  </span>
                  {lastTaskResult.task_request.redaction_applied && (
                    <span className="rounded bg-[#1a1a1f] px-2 py-0.5 text-zinc-200">
                      Redacted
                    </span>
                  )}
                  {lastTaskResult.task_request.prompt_injection_detected && (
                    <span className="rounded bg-[#19191f] px-2 py-0.5 text-rose-300">
                      Injection Isolated
                    </span>
                  )}
                </div>
                <p className="mt-2 text-zinc-300">{lastTaskResult.run.rationale_summary}</p>
                <p className="mt-1 text-zinc-400">{lastTaskResult.run.uncertainty_notes}</p>
              </div>
            )}
          </section>
        )}

        <section className="rounded-xl border border-white/[0.068] bg-[#141417] p-5">
          <h2 className="text-lg font-medium text-white">OPA &amp; Human-Gated Tool Proposals</h2>
          <div className="mt-4 space-y-3">
            {(overview?.tool_proposals ?? []).map((prop) => (
              <div
                key={prop.id}
                className="rounded-lg border border-white/[0.068] bg-[#0e0e11]/70 p-4 text-sm"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="font-mono text-xs text-white">
                    {prop.tool_action} -&gt; {prop.target_resource_type}
                  </div>
                  <div className="flex items-center gap-2 text-xs">
                    <span
                      className={`rounded px-2 py-0.5 ${
                        prop.opa_allowed
                          ? "bg-[#1a1a1f] text-zinc-200"
                          : "bg-[#19191f] text-rose-300"
                      }`}
                    >
                      {prop.opa_allowed ? "OPA Allowed" : "OPA Denied"}
                    </span>
                    <span className="rounded bg-[#1c1c20] px-2 py-0.5 text-zinc-300">
                      {prop.status}
                    </span>
                  </div>
                </div>
                <p className="mt-1 text-xs text-zinc-400">{prop.opa_decision_reason}</p>
                {canManage && prop.status === "pending_human_approval" && prop.opa_allowed && (
                  <div className="mt-3 flex gap-2">
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => void handleDecideProposal(prop.id, "approved")}
                      className="vf-btn-primary px-3 py-1 text-xs font-medium"
                    >
                      Approve Tool Action
                    </button>
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => void handleDecideProposal(prop.id, "rejected")}
                      className="vf-btn-danger px-3 py-1 text-xs"
                    >
                      Reject
                    </button>
                  </div>
                )}
              </div>
            ))}
            {overview && overview.tool_proposals.length === 0 && (
              <p className="text-sm text-zinc-400">No AI tool proposals recorded yet.</p>
            )}
          </div>
        </section>
      </div>

      {/* RAG Knowledge Base & Evaluations */}
      <div className="grid gap-6 lg:grid-cols-2">
        <section className="rounded-xl border border-white/[0.068] bg-[#141417] p-5">
          <h2 className="text-lg font-medium text-white">Tenant-Isolated RAG Knowledge</h2>
          <form onSubmit={handleSearchKnowledge} className="mt-3 flex gap-2">
            <input
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search tenant-approved security docs..."
              className="flex-1 rounded border border-white/[0.1] bg-[#0e0e11] px-3 py-1.5 text-sm text-zinc-100"
            />
            <button
              type="submit"
              disabled={busy}
              className="vf-btn-secondary h-8 px-4 text-xs"
            >
              Search
            </button>
          </form>
          {searchHits.length > 0 && (
            <div className="mt-3 space-y-2">
              {searchHits.map((h) => (
                <div
                  key={h.chunk_id}
                  className="rounded border border-white/[0.068] bg-[#0e0e11] p-3 text-xs text-zinc-300"
                >
                  <div className="font-medium text-white">
                    {h.title} ({h.source_type})
                  </div>
                  <p className="mt-1 text-zinc-400">{h.excerpt}</p>
                </div>
              ))}
            </div>
          )}

          {canManage && (
            <form onSubmit={handleIndexKnowledge} className="mt-4 space-y-2 border-t border-white/[0.08] pt-4 text-sm">
              <div className="text-xs font-medium uppercase text-zinc-400">
                Index Curated Document
              </div>
              <div className="grid gap-2 sm:grid-cols-2">
                <input
                  value={docSlug}
                  onChange={(e) => setDocSlug(e.target.value)}
                  placeholder="slug"
                  required
                  className="rounded border border-white/[0.1] bg-[#0e0e11] px-3 py-1.5 text-zinc-100"
                />
                <Select
                  size="sm"
                  value={docType}
                  onChange={(e) =>
                    setDocType(e.target.value as (typeof KNOWLEDGE_TYPES)[number])
                  }
                >
                  {KNOWLEDGE_TYPES.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </Select>
              </div>
              <input
                value={docTitle}
                onChange={(e) => setDocTitle(e.target.value)}
                placeholder="Document title"
                required
                className="w-full rounded border border-white/[0.1] bg-[#0e0e11] px-3 py-1.5 text-zinc-100"
              />
              <input
                value={docUri}
                onChange={(e) => setDocUri(e.target.value)}
                placeholder="curated://..."
                required
                className="w-full rounded border border-white/[0.1] bg-[#0e0e11] px-3 py-1.5 text-zinc-100"
              />
              <textarea
                rows={2}
                value={docContent}
                onChange={(e) => setDocContent(e.target.value)}
                required
                className="w-full rounded border border-white/[0.1] bg-[#0e0e11] px-3 py-1.5 text-zinc-100"
              />
              <button
                type="submit"
                disabled={busy}
                className="vf-btn-primary px-3 py-1.5 text-xs font-medium"
              >
                Index Curated Knowledge
              </button>
            </form>
          )}
        </section>

        <section className="rounded-xl border border-white/[0.068] bg-[#141417] p-5">
          <h2 className="text-lg font-medium text-white">Deterministic Model Evaluations</h2>
          {canManage && (
            <form onSubmit={handleRecordEval} className="mt-3 space-y-2 text-sm">
              <div className="grid gap-2 sm:grid-cols-2">
                <input
                  value={evalModelSlug}
                  onChange={(e) => setEvalModelSlug(e.target.value)}
                  placeholder="Model slug"
                  className="rounded border border-white/[0.1] bg-[#0e0e11] px-3 py-1.5 text-zinc-100"
                />
                <input
                  value={evalSuiteName}
                  onChange={(e) => setEvalSuiteName(e.target.value)}
                  placeholder="Suite name"
                  className="rounded border border-white/[0.1] bg-[#0e0e11] px-3 py-1.5 text-zinc-100"
                />
              </div>
              <div className="grid gap-2 sm:grid-cols-3">
                <input
                  type="number"
                  value={evalSamples}
                  onChange={(e) => setEvalSamples(e.target.value)}
                  placeholder="Samples"
                  className="rounded border border-white/[0.1] bg-[#0e0e11] px-3 py-1.5 text-zinc-100"
                />
                <input
                  type="number"
                  step="0.01"
                  value={evalTpr}
                  onChange={(e) => setEvalTpr(e.target.value)}
                  placeholder="TPR"
                  className="rounded border border-white/[0.1] bg-[#0e0e11] px-3 py-1.5 text-zinc-100"
                />
                <input
                  type="number"
                  step="0.01"
                  value={evalFpr}
                  onChange={(e) => setEvalFpr(e.target.value)}
                  placeholder="FPR"
                  className="rounded border border-white/[0.1] bg-[#0e0e11] px-3 py-1.5 text-zinc-100"
                />
              </div>
              <button
                type="submit"
                disabled={busy}
                className="vf-btn-primary px-3 py-1.5 text-xs font-medium"
              >
                Record Evaluation Benchmark
              </button>
            </form>
          )}
          <div className="mt-4 space-y-2">
            {(overview?.evaluations ?? []).map((ev) => (
              <div
                key={ev.id}
                className="flex items-center justify-between rounded border border-white/[0.068] bg-[#0e0e11]/70 px-3 py-2 text-xs"
              >
                <div>
                  <span className="font-mono text-white">{ev.model_slug}</span> · {ev.suite_name} (n=
                  {ev.sample_count})
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-zinc-300">
                    TPR {(ev.true_positive_rate * 100).toFixed(0)}% / FPR{" "}
                    {(ev.false_positive_rate * 100).toFixed(0)}%
                  </span>
                  <span
                    className={`rounded px-2 py-0.5 ${
                      ev.regression_passed
                        ? "bg-[#1a1a1f] text-zinc-200"
                        : "bg-[#19191f] text-rose-300"
                    }`}
                  >
                    {ev.regression_passed ? "PASS" : "FAIL"}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>

      {/* Append-Only AI Audit Trail */}
      <section className="rounded-xl border border-white/[0.068] bg-[#141417] p-5">
        <h2 className="text-lg font-medium text-white">Immutable AI Gateway Audit Trail</h2>
        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-white/[0.068] uppercase text-zinc-400">
                <th className="py-2 pr-4">Timestamp</th>
                <th className="py-2 pr-4">Action</th>
                <th className="py-2 pr-4">Actor</th>
                <th className="py-2 pr-4">Model</th>
                <th className="py-2 pr-4">Classification</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06] text-zinc-300">
              {(overview?.audit_events ?? []).map((evt) => (
                <tr key={evt.id}>
                  <td className="py-2 pr-4 font-mono">{formatUtc(evt.occurred_at)}</td>
                  <td className="py-2 pr-4 font-medium text-white">{evt.action}</td>
                  <td className="py-2 pr-4">{evt.actor_email}</td>
                  <td className="py-2 pr-4 font-mono">{evt.model_slug || "—"}</td>
                  <td className="py-2 pr-4">{evt.data_classification || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

export default function AiGovernancePage() {
  const params = useParams<{ orgId: string }>();
  const orgId = params.orgId;
  return (
    <OrgShell orgId={orgId}>
      {({ auth, membership }) => (
        <AiGovernanceContent
          orgId={orgId}
          membership={membership}
          csrfToken={auth.csrf_token ?? ""}
        />
      )}
    </OrgShell>
  );
}
