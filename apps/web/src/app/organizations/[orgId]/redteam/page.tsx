"use client";

import { use, useCallback, useEffect, useState } from "react";
import OrgShell, { hasPermission } from "@/components/OrgShell";
import { Select } from "@/components/ui/Select";
import { apiFetch } from "@/lib/api";
import type { RedTeamOverview } from "@/lib/types";

export default function RedTeamPage({
  params,
}: {
  params: Promise<{ orgId: string }>;
}) {
  const { orgId } = use(params);
  const [overview, setOverview] = useState<RedTeamOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  // Request Session Form
  const [title, setTitle] = useState("Lab Auth & IDOR Hypothesis Exploration");
  const [objective, setObjective] = useState(
    "Explore isolated VulnLab API authentication and BOLA/IDOR endpoints within bounded tool and token budgets.",
  );
  const [engine, setEngine] = useState<"strix" | "pentagi">("strix");
  const [targetUrl, setTargetUrl] = useState("http://crapi-web:8080");
  const [selectedTools, setSelectedTools] = useState<string[]>([
    "http_probe",
    "dom_inspect",
    "note_hypothesis",
  ]);
  const [maxDuration, setMaxDuration] = useState(900);
  const [maxToolCalls, setMaxToolCalls] = useState(25);
  const [maxTokens, setMaxTokens] = useState(50000);

  // Active Session Action State
  const [selectedSessionId, setSelectedSessionId] = useState("");
  const [toolName, setToolName] = useState("http_probe");
  const [toolTargetUrl, setToolTargetUrl] = useState("http://crapi-web:8080/api/orders/1002");
  const [toolInputSummary, setToolInputSummary] = useState(
    "GET /api/orders/1002 with disposable student token to check cross-account read access",
  );
  const [estimatedTokens, setEstimatedTokens] = useState(450);

  // Hypothesis Recording State
  const [obsTitle, setObsTitle] = useState(
    "Potential BOLA/IDOR on /api/orders/{id} in isolated lab",
  );
  const [obsCategory, setObsCategory] = useState("bola_idor");
  const [obsSeverity, setObsSeverity] = useState<
    "info" | "low" | "medium" | "high" | "critical"
  >("high");
  const [obsEvidence, setObsEvidence] = useState(
    "Disposable student account A received HTTP 200 with order metadata belonging to disposable account B on http://vulnlab-api:8090/api/orders/1002.",
  );

  // Review Note State
  const [reviewNote, setReviewNote] = useState(
    "Independently reproduced in isolated lab workspace; confirmed missing ownership check.",
  );

  // Benchmark Form State
  const [groundTruthCsv, setGroundTruthCsv] = useState(
    "lab-bola-order-read,lab-jwt-alg-none,lab-sqli-search,lab-reflected-xss",
  );
  const [aiCsv, setAiCsv] = useState("lab-bola-order-read,lab-jwt-alg-none");
  const [zapCsv, setZapCsv] = useState("lab-sqli-search,lab-reflected-xss");
  const [nucleiCsv, setNucleiCsv] = useState("lab-jwt-alg-none,lab-sqli-search");

  const reloadOverview = useCallback(async () => {
    try {
      const data = await apiFetch<RedTeamOverview>(
        `/api/v1/organizations/${orgId}/redteam/overview`,
      );
      setOverview(data);
      if (data.sessions.length > 0 && !selectedSessionId) {
        setSelectedSessionId(data.sessions[0].id);
      }
      setError(null);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to load AI Red-Team overview",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, selectedSessionId]);

  useEffect(() => {
    let active = true;
    void apiFetch<RedTeamOverview>(
      `/api/v1/organizations/${orgId}/redteam/overview`,
    )
      .then((data) => {
        if (!active) return;
        setOverview(data);
        if (data.sessions.length > 0) {
          setSelectedSessionId((prev) => prev || data.sessions[0].id);
        }
        setError(null);
        setLoading(false);
      })
      .catch((err) => {
        if (!active) return;
        setError(
          err instanceof Error
            ? err.message
            : "Failed to load AI Red-Team overview",
        );
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [orgId]);

  const toggleTool = (name: string) => {
    setSelectedTools((prev) =>
      prev.includes(name) ? prev.filter((t) => t !== name) : [...prev, name],
    );
  };

  return (
    <OrgShell orgId={orgId}>
      {({ auth, membership }) => {
        const canRequest = hasPermission(membership, "redteam:request");
        const canApprove = hasPermission(membership, "redteam:approve");
        const canExecute = hasPermission(membership, "redteam:execute");
        const canReview = hasPermission(membership, "redteam:review");

        const handleRequestSession = async (e: React.FormEvent) => {
          e.preventDefault();
          setError(null);
          setStatusMsg(null);
          try {
            await apiFetch(`/api/v1/organizations/${orgId}/redteam/sessions`, {
              method: "POST",
              csrfToken: auth.csrf_token,
              body: JSON.stringify({
                title,
                objective,
                engine,
                tool_allowlist: selectedTools,
                target_urls: [targetUrl.trim()],
                max_duration_seconds: Number(maxDuration),
                max_tool_calls: Number(maxToolCalls),
                max_tokens: Number(maxTokens),
              }),
            });
            setStatusMsg(
              "Session requested in pending state. A different human reviewer must approve before execution.",
            );
            await reloadOverview();
          } catch (err) {
            setError(
              err instanceof Error ? err.message : "Failed to request session",
            );
          }
        };

        const handleDecision = async (
          sessionId: string,
          decision: "approve" | "reject",
        ) => {
          setError(null);
          setStatusMsg(null);
          try {
            await apiFetch(
              `/api/v1/organizations/${orgId}/redteam/sessions/${sessionId}/decision`,
              {
                method: "POST",
                csrfToken: auth.csrf_token,
                body: JSON.stringify({
                  decision,
                  approval_ttl_minutes: 30,
                  reason:
                    decision === "approve"
                      ? "Approved for isolated lab assessment"
                      : "Rejected by security reviewer",
                }),
              },
            );
            setStatusMsg(`Session ${decision}d.`);
            await reloadOverview();
          } catch (err) {
            setError(
              err instanceof Error ? err.message : "Failed to record decision",
            );
          }
        };

        const handleStart = async (sessionId: string) => {
          setError(null);
          setStatusMsg(null);
          try {
            await apiFetch(
              `/api/v1/organizations/${orgId}/redteam/sessions/${sessionId}/start`,
              {
                method: "POST",
                csrfToken: auth.csrf_token,
              },
            );
            setStatusMsg("Isolated AI red-team session started.");
            await reloadOverview();
          } catch (err) {
            setError(
              err instanceof Error ? err.message : "Failed to start session",
            );
          }
        };

        const handleClose = async (
          sessionId: string,
          finalStatus: "completed" | "terminated",
        ) => {
          setError(null);
          setStatusMsg(null);
          try {
            await apiFetch(
              `/api/v1/organizations/${orgId}/redteam/sessions/${sessionId}/close`,
              {
                method: "POST",
                csrfToken: auth.csrf_token,
                body: JSON.stringify({
                  final_status: finalStatus,
                  end_reason: `Operator ${finalStatus} session`,
                  cleanup_attested: true,
                  cleanup_summary:
                    "Ephemeral sandbox tmpfs wiped and container terminated.",
                }),
              },
            );
            setStatusMsg(
              `Session ${finalStatus} with ephemeral cleanup attestation.`,
            );
            await reloadOverview();
          } catch (err) {
            setError(
              err instanceof Error ? err.message : "Failed to close session",
            );
          }
        };

        const handleToolCall = async (e: React.FormEvent) => {
          e.preventDefault();
          if (!selectedSessionId) return;
          setError(null);
          setStatusMsg(null);
          try {
            await apiFetch(
              `/api/v1/organizations/${orgId}/redteam/sessions/${selectedSessionId}/tool-calls`,
              {
                method: "POST",
                csrfToken: auth.csrf_token,
                body: JSON.stringify({
                  tool_name: toolName,
                  target_url: toolTargetUrl.trim() || null,
                  input_summary: toolInputSummary,
                  estimated_tokens: Number(estimatedTokens),
                }),
              },
            );
            setStatusMsg(`Executed bounded tool '${toolName}' in isolated sandbox.`);
            await reloadOverview();
          } catch (err) {
            setError(
              err instanceof Error ? err.message : "Tool execution rejected",
            );
            await reloadOverview();
          }
        };

        const handleRecordObservation = async (e: React.FormEvent) => {
          e.preventDefault();
          if (!selectedSessionId) return;
          setError(null);
          setStatusMsg(null);
          try {
            await apiFetch(
              `/api/v1/organizations/${orgId}/redteam/sessions/${selectedSessionId}/observations`,
              {
                method: "POST",
                csrfToken: auth.csrf_token,
                body: JSON.stringify({
                  title: obsTitle,
                  category: obsCategory,
                  severity: obsSeverity,
                  evidence_summary: obsEvidence,
                }),
              },
            );
            setStatusMsg(
              "Recorded AI observation as 'hypothesis' (requires independent human review to confirm).",
            );
            await reloadOverview();
          } catch (err) {
            setError(
              err instanceof Error
                ? err.message
                : "Failed to record hypothesis",
            );
          }
        };

        const handleReviewObservation = async (
          obsId: string,
          decision: "confirmed" | "rejected",
        ) => {
          setError(null);
          setStatusMsg(null);
          try {
            await apiFetch(
              `/api/v1/organizations/${orgId}/redteam/observations/${obsId}/review`,
              {
                method: "POST",
                csrfToken: auth.csrf_token,
                body: JSON.stringify({
                  decision,
                  review_note: reviewNote,
                }),
              },
            );
            setStatusMsg(`Observation marked as '${decision}'.`);
            await reloadOverview();
          } catch (err) {
            setError(
              err instanceof Error
                ? err.message
                : "Observation review failed",
            );
          }
        };

        const handleCreateBenchmark = async (e: React.FormEvent) => {
          e.preventDefault();
          if (!selectedSessionId) return;
          setError(null);
          setStatusMsg(null);
          const parseCsv = (raw: string) =>
            raw
              .split(",")
              .map((s) => s.trim())
              .filter(Boolean);
          try {
            await apiFetch(
              `/api/v1/organizations/${orgId}/redteam/sessions/${selectedSessionId}/benchmarks`,
              {
                method: "POST",
                csrfToken: auth.csrf_token,
                body: JSON.stringify({
                  ground_truth_slugs: parseCsv(groundTruthCsv),
                  ai_detected_slugs: parseCsv(aiCsv),
                  zap_detected_slugs: parseCsv(zapCsv),
                  nuclei_detected_slugs: parseCsv(nucleiCsv),
                }),
              },
            );
            setStatusMsg(
              "Recorded immutable benchmark comparing AI red-team vs ZAP & Nuclei.",
            );
            await reloadOverview();
          } catch (err) {
            setError(
              err instanceof Error
                ? err.message
                : "Failed to create benchmark",
            );
          }
        };

        return (
          <div className="space-y-8">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div>
                <h1 className="text-2xl font-semibold text-white">
                  Optional Isolated AI Red-Team Sandbox (Phase 15)
                </h1>
                <p className="mt-1 text-sm text-zinc-400">
                  Experimental Strix / PentAGI assessment sandbox strictly confined to
                  isolated Learning Lab targets (`lab_internal`), with per-session
                  human approval, strict tool/token budgets, and hypothesis-only
                  outputs until independent human confirmation.
                </p>
              </div>
              <span className="rounded-full border border-white/[0.08] bg-[#1a1a1f] px-3 py-1 text-xs font-medium text-zinc-200">
                Mode: {overview?.execution_mode ?? "isolated_lab_only_human_approved"}
              </span>
            </div>

            {error && (
              <div className="rounded-lg border border-white/[0.08] bg-[#131317] p-4 text-sm text-zinc-200">
                {error}
              </div>
            )}
            {statusMsg && (
              <div className="rounded-lg border border-white/[0.08] bg-[#121614] p-4 text-sm text-zinc-200">
                {statusMsg}
              </div>
            )}

            {loading || !overview ? (
              <div className="text-sm text-zinc-400">
                Loading Phase 15 AI Red-Team Sandbox posture...
              </div>
            ) : (
              <>
                {/* Isolation & Tool Policy Cards */}
                <div className="grid gap-4 md:grid-cols-3">
                  <div className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-4">
                    <h2 className="text-sm font-semibold text-zinc-200">
                      Red-Team Sandbox Compose Isolation
                    </h2>
                    <p className="mt-2 text-xs text-zinc-400">
                      Status:{" "}
                      <span
                        className={
                          overview.sandbox_isolation.verified
                            ? "font-semibold text-zinc-200"
                            : "font-semibold text-rose-400"
                        }
                      >
                        {overview.sandbox_isolation.verified
                          ? "VERIFIED (No Internet / No Control-Plane Access)"
                          : "VIOLATION DETECTED"}
                      </span>
                    </p>
                    <p className="mt-1 text-xs text-zinc-500">
                      Services checked: {overview.sandbox_isolation.services_checked}
                    </p>
                  </div>

                  <div className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-4">
                    <h2 className="text-sm font-semibold text-zinc-200">
                      Learning Lab Target Network Isolation
                    </h2>
                    <p className="mt-2 text-xs text-zinc-400">
                      Status:{" "}
                      <span
                        className={
                          overview.lab_isolation.verified
                            ? "font-semibold text-zinc-200"
                            : "font-semibold text-rose-400"
                        }
                      >
                        {overview.lab_isolation.verified
                          ? "VERIFIED (internal: true)"
                          : "VIOLATION DETECTED"}
                      </span>
                    </p>
                    <p className="mt-1 text-xs text-zinc-500">
                      Lab services checked: {overview.lab_isolation.services_checked}
                    </p>
                  </div>

                  <div className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-4">
                    <h2 className="text-sm font-semibold text-zinc-200">
                      Hard Safety Invariants
                    </h2>
                    <ul className="mt-2 space-y-1 text-xs text-zinc-400">
                      <li>• Per-session human approval (SoD enforced)</li>
                      <li>• AI observations start as `hypothesis` only</li>
                      <li>• Forbidden: {overview.forbidden_tools.slice(0, 5).join(", ")}</li>
                    </ul>
                  </div>
                </div>

                {/* Request Session & Active Session Controls */}
                <div className="grid gap-6 lg:grid-cols-2">
                  {canRequest && (
                    <form
                      onSubmit={handleRequestSession}
                      className="space-y-4 rounded-lg border border-white/[0.068] bg-[#141417] p-5"
                    >
                      <h2 className="text-base font-semibold text-white">
                        1. Request Bounded AI Red-Team Session (Lab Only)
                      </h2>
                      <div>
                        <label className="block text-xs text-zinc-400">Title</label>
                        <input
                          type="text"
                          value={title}
                          onChange={(e) => setTitle(e.target.value)}
                          className="mt-1 vf-input"
                          required
                        />
                      </div>
                      <div>
                        <label className="block text-xs text-zinc-400">
                          Objective
                        </label>
                        <textarea
                          value={objective}
                          onChange={(e) => setObjective(e.target.value)}
                          rows={2}
                          className="mt-1 vf-input"
                          required
                        />
                      </div>
                      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                        <div>
                          <label className="block text-xs text-zinc-400">
                            Sandbox Engine
                          </label>
                          <Select
                            value={engine}
                            onChange={(e) =>
                              setEngine(e.target.value as "strix" | "pentagi")
                            }
                            className="mt-1"
                          >
                            <option value="strix">Strix Sandbox</option>
                            <option value="pentagi">PentAGI Sandbox</option>
                          </Select>
                        </div>
                        <div>
                          <label className="block text-xs text-zinc-400">
                            Isolated Lab Target URL
                          </label>
                          <input
                            type="text"
                            value={targetUrl}
                            onChange={(e) => setTargetUrl(e.target.value)}
                            className="mt-1 vf-input"
                            required
                          />
                        </div>
                      </div>
                      <div>
                        <label className="block text-xs text-zinc-400">
                          Approved Tool Allowlist
                        </label>
                        <div className="mt-1 flex flex-wrap gap-2">
                          {overview.allowed_tools.map((t) => (
                            <button
                              key={t.name}
                              type="button"
                              onClick={() => toggleTool(t.name)}
                              className={`rounded border px-2.5 py-1 text-xs ${
                                selectedTools.includes(t.name)
                                  ? "border-[#3b72f2]/45 bg-[#162033] text-[#93c5fd]"
                                  : "border-white/[0.1] bg-[#0e0e11] text-zinc-400"
                              }`}
                            >
                              {t.name}
                            </button>
                          ))}
                        </div>
                      </div>
                      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                        <div>
                          <label className="block text-xs text-zinc-400">
                            Max Duration (s)
                          </label>
                          <input
                            type="number"
                            value={maxDuration}
                            onChange={(e) => setMaxDuration(Number(e.target.value))}
                            min={60}
                            max={3600}
                            className="mt-1 vf-input"
                          />
                        </div>
                        <div>
                          <label className="block text-xs text-zinc-400">
                            Max Tool Calls
                          </label>
                          <input
                            type="number"
                            value={maxToolCalls}
                            onChange={(e) =>
                              setMaxToolCalls(Number(e.target.value))
                            }
                            min={1}
                            max={500}
                            className="mt-1 vf-input"
                          />
                        </div>
                        <div>
                          <label className="block text-xs text-zinc-400">
                            Max Tokens
                          </label>
                          <input
                            type="number"
                            value={maxTokens}
                            onChange={(e) => setMaxTokens(Number(e.target.value))}
                            min={1000}
                            max={2000000}
                            className="mt-1 vf-input"
                          />
                        </div>
                      </div>
                      <button
                        type="submit"
                        className="vf-btn-primary h-8 px-4 text-xs"
                      >
                        Request Session (Requires Independent Approval)
                      </button>
                    </form>
                  )}

                  {canExecute && (
                    <div className="space-y-4 rounded-lg border border-white/[0.068] bg-[#141417] p-5">
                      <h2 className="text-base font-semibold text-white">
                        2. Execute Bounded Tool Call & Record Hypothesis
                      </h2>
                      <div>
                        <label className="block text-xs text-zinc-400">
                          Target Session
                        </label>
                        <Select
                          value={selectedSessionId}
                          onChange={(e) => setSelectedSessionId(e.target.value)}
                          className="mt-1"
                        >
                          <option value="">-- Select Session --</option>
                          {overview.sessions.map((s) => (
                            <option key={s.id} value={s.id}>
                              {s.title} [{s.status}] ({s.tool_calls_used}/
                              {s.max_tool_calls} calls)
                            </option>
                          ))}
                        </Select>
                      </div>

                      <form onSubmit={handleToolCall} className="space-y-3 border-t border-white/[0.08] pt-3">
                        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                          <div>
                            <label className="block text-xs text-zinc-400">
                              Tool Name
                            </label>
                            <Select
                              value={toolName}
                              onChange={(e) => setToolName(e.target.value)}
                              className="mt-1"
                            >
                              {overview.allowed_tools.map((t) => (
                                <option key={t.name} value={t.name}>
                                  {t.name}
                                </option>
                              ))}
                            </Select>
                          </div>
                          <div>
                            <label className="block text-xs text-zinc-400">
                              Estimated Tokens
                            </label>
                            <input
                              type="number"
                              value={estimatedTokens}
                              onChange={(e) =>
                                setEstimatedTokens(Number(e.target.value))
                              }
                              className="mt-1 vf-input"
                            />
                          </div>
                        </div>
                        <div>
                          <label className="block text-xs text-zinc-400">
                            Target URL (Checked Against Session Allowlist)
                          </label>
                          <input
                            type="text"
                            value={toolTargetUrl}
                            onChange={(e) => setToolTargetUrl(e.target.value)}
                            className="mt-1 vf-input"
                          />
                        </div>
                        <div>
                          <label className="block text-xs text-zinc-400">
                            Input Summary (Redacted Before Storage)
                          </label>
                          <input
                            type="text"
                            value={toolInputSummary}
                            onChange={(e) => setToolInputSummary(e.target.value)}
                            className="mt-1 vf-input"
                          />
                        </div>
                        <button
                          type="submit"
                          disabled={!selectedSessionId}
                          className="vf-btn-primary px-3.5 py-1.5 text-xs font-medium"
                        >
                          Execute Tool Call
                        </button>
                      </form>

                      <form
                        onSubmit={handleRecordObservation}
                        className="space-y-3 border-t border-white/[0.08] pt-3"
                      >
                        <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                          <input
                            type="text"
                            value={obsTitle}
                            onChange={(e) => setObsTitle(e.target.value)}
                            placeholder="Hypothesis title"
                            className="vf-input text-xs sm:col-span-2"
                          />
                          <Select
                            size="sm"
                            value={obsSeverity}
                            onChange={(e) =>
                              setObsSeverity(
                                e.target.value as
                                  | "info"
                                  | "low"
                                  | "medium"
                                  | "high"
                                  | "critical",
                              )
                            }
                          >
                            <option value="critical">critical</option>
                            <option value="high">high</option>
                            <option value="medium">medium</option>
                            <option value="low">low</option>
                            <option value="info">info</option>
                          </Select>
                        </div>
                        <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                          <input
                            type="text"
                            value={obsCategory}
                            onChange={(e) => setObsCategory(e.target.value)}
                            placeholder="Category"
                            className="vf-input text-xs"
                          />
                          <input
                            type="text"
                            value={obsEvidence}
                            onChange={(e) => setObsEvidence(e.target.value)}
                            placeholder="Redacted evidence summary"
                            className="vf-input text-xs sm:col-span-2"
                          />
                        </div>
                        <button
                          type="submit"
                          disabled={!selectedSessionId}
                          className="vf-btn-warning h-8 px-3.5 text-xs"
                        >
                          Record AI Hypothesis (Unverified)
                        </button>
                      </form>
                    </div>
                  )}
                </div>

                {/* Sessions Table */}
                <div className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-5">
                  <h2 className="text-base font-semibold text-white">
                    AI Red-Team Sessions ({overview.sessions.length})
                  </h2>
                  <div className="mt-3 overflow-x-auto">
                    <table className="w-full text-left text-xs text-zinc-300">
                      <thead className="border-b border-white/[0.068] text-zinc-400">
                        <tr>
                          <th className="py-2 pr-3">Title & Engine</th>
                          <th className="py-2 pr-3">Status</th>
                          <th className="py-2 pr-3">Targets & Tools</th>
                          <th className="py-2 pr-3">Budget Usage</th>
                          <th className="py-2 pr-3">Cleanup Attested</th>
                          <th className="py-2">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-white/[0.06]">
                        {overview.sessions.map((s) => (
                          <tr key={s.id}>
                            <td className="py-2.5 pr-3">
                              <div className="font-medium text-white">
                                {s.title}
                              </div>
                              <div className="text-zinc-500">
                                Engine: {s.engine}
                              </div>
                            </td>
                            <td className="py-2.5 pr-3">
                              <span className="rounded border border-white/[0.08] bg-[#1c1c20] px-2 py-0.5 font-mono">
                                {s.status}
                              </span>
                            </td>
                            <td className="py-2.5 pr-3">
                              <div>{s.target_urls.join(", ")}</div>
                              <div className="text-zinc-500">
                                Tools: {s.tool_allowlist.join(", ")}
                              </div>
                            </td>
                            <td className="py-2.5 pr-3">
                              <div>
                                Calls: {s.tool_calls_used} / {s.max_tool_calls}
                              </div>
                              <div>
                                Tokens: {s.tokens_used} / {s.max_tokens}
                              </div>
                            </td>
                            <td className="py-2.5 pr-3">
                              {s.cleanup_attested ? "Yes" : "Pending"}
                            </td>
                            <td className="py-2.5">
                              <div className="flex flex-wrap gap-1.5">
                                {canApprove && s.status === "requested" && (
                                  <>
                                    <button
                                      type="button"
                                      onClick={() =>
                                        handleDecision(s.id, "approve")
                                      }
                                      className="vf-btn-primary px-2 py-1"
                                    >
                                      Approve
                                    </button>
                                    <button
                                      type="button"
                                      onClick={() =>
                                        handleDecision(s.id, "reject")
                                      }
                                      className="vf-btn-danger px-2 py-1"
                                    >
                                      Reject
                                    </button>
                                  </>
                                )}
                                {canExecute && s.status === "approved" && (
                                  <button
                                    type="button"
                                    onClick={() => handleStart(s.id)}
                                    className="vf-btn-primary px-2 py-1"
                                  >
                                    Start
                                  </button>
                                )}
                                {canExecute && s.status === "running" && (
                                  <>
                                    <button
                                      type="button"
                                      onClick={() =>
                                        handleClose(s.id, "completed")
                                      }
                                      className="vf-btn-primary px-2 py-1"
                                    >
                                      Complete & Wipe
                                    </button>
                                    <button
                                      type="button"
                                      onClick={() =>
                                        handleClose(s.id, "terminated")
                                      }
                                      className="vf-btn-danger px-2 py-1"
                                    >
                                      Terminate
                                    </button>
                                  </>
                                )}
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Observations (Hypothesis vs Confirmed) */}
                <div className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-5">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <h2 className="text-base font-semibold text-white">
                      AI Observations — Hypothesis vs. Confirmed ({overview.observations.length})
                    </h2>
                    {canReview && (
                      <input
                        type="text"
                        value={reviewNote}
                        onChange={(e) => setReviewNote(e.target.value)}
                        placeholder="Review note (min 12 chars)"
                        className="w-96 rounded border border-white/[0.1] bg-[#0e0e11] px-3 py-1 text-xs text-white"
                      />
                    )}
                  </div>
                  <div className="mt-3 space-y-2">
                    {overview.observations.map((o) => (
                      <div
                        key={o.id}
                        className="flex flex-wrap items-center justify-between gap-3 rounded border border-white/[0.068] bg-[#0e0e11]/70 p-3 text-xs"
                      >
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-semibold text-white">
                              {o.title}
                            </span>
                            <span
                              className={`inline-flex items-center gap-1.5 rounded-full border border-white/[0.08] bg-[#19191e] px-2.5 py-0.5 text-[11px] font-medium ${
                                o.classification === "confirmed"
                                  ? "text-zinc-200"
                                  : o.classification === "rejected"
                                    ? "text-rose-300/90"
                                    : "text-amber-300/90"
                              }`}
                            >
                              <span
                                className={`h-1.5 w-1.5 rounded-full ${
                                  o.classification === "confirmed"
                                    ? "bg-emerald-400"
                                    : o.classification === "rejected"
                                      ? "bg-rose-400"
                                      : "bg-amber-400"
                                }`}
                              />
                              {o.classification.toUpperCase()}
                            </span>
                            <span className="text-zinc-400">
                              [{o.severity} / {o.category}]
                            </span>
                          </div>
                          <p className="mt-1 text-zinc-300">
                            {o.evidence_summary}
                          </p>
                          <p className="mt-0.5 font-mono text-[11px] text-zinc-500">
                            SHA-256: {o.evidence_sha256}
                            {o.review_note ? ` • Review: ${o.review_note}` : ""}
                          </p>
                        </div>
                        {canReview && o.classification === "hypothesis" && (
                          <div className="flex gap-2">
                            <button
                              type="button"
                              onClick={() =>
                                handleReviewObservation(o.id, "confirmed")
                              }
                              className="vf-btn-primary px-2.5 py-1"
                            >
                              Confirm (Independent Human)
                            </button>
                            <button
                              type="button"
                              onClick={() =>
                                handleReviewObservation(o.id, "rejected")
                              }
                              className="vf-btn-danger px-2.5 py-1"
                            >
                              Reject
                            </button>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Benchmark Comparison vs ZAP and Nuclei */}
                <div className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-5">
                  <h2 className="text-base font-semibold text-white">
                    Benchmark Comparison: AI Red-Team vs. OWASP ZAP & ProjectDiscovery Nuclei
                  </h2>
                  {canReview && (
                    <form
                      onSubmit={handleCreateBenchmark}
                      className="mt-3 grid gap-3 md:grid-cols-4"
                    >
                      <input
                        type="text"
                        value={groundTruthCsv}
                        onChange={(e) => setGroundTruthCsv(e.target.value)}
                        placeholder="Ground truth slugs (CSV)"
                        className="rounded border border-white/[0.1] bg-[#0e0e11] px-2.5 py-1.5 text-xs text-white"
                      />
                      <input
                        type="text"
                        value={aiCsv}
                        onChange={(e) => setAiCsv(e.target.value)}
                        placeholder="AI confirmed slugs (CSV)"
                        className="rounded border border-white/[0.1] bg-[#0e0e11] px-2.5 py-1.5 text-xs text-white"
                      />
                      <input
                        type="text"
                        value={zapCsv}
                        onChange={(e) => setZapCsv(e.target.value)}
                        placeholder="ZAP detected slugs (CSV)"
                        className="rounded border border-white/[0.1] bg-[#0e0e11] px-2.5 py-1.5 text-xs text-white"
                      />
                      <div className="flex flex-col gap-2 sm:flex-row">
                        <input
                          type="text"
                          value={nucleiCsv}
                          onChange={(e) => setNucleiCsv(e.target.value)}
                          placeholder="Nuclei detected slugs (CSV)"
                          className="vf-input text-xs"
                        />
                        <button
                          type="submit"
                          disabled={!selectedSessionId}
                          className="vf-btn-primary shrink-0 px-3.5 py-1.5 text-xs font-medium"
                        >
                          Compare
                        </button>
                      </div>
                    </form>
                  )}

                  <div className="mt-4 space-y-2">
                    {overview.benchmarks.map((b) => (
                      <div
                        key={b.id}
                        className="rounded border border-white/[0.068] bg-[#0e0e11]/70 p-3 text-xs text-zinc-300"
                      >
                        <div className="flex flex-wrap gap-4 font-medium text-white">
                          <span>
                            Ground Truth: {b.metrics_json.ground_truth_count}
                          </span>
                          <span>
                            AI Recall:{" "}
                            {(b.metrics_json.recall.ai_redteam * 100).toFixed(1)}%
                          </span>
                          <span>
                            ZAP Recall:{" "}
                            {(b.metrics_json.recall.zap * 100).toFixed(1)}%
                          </span>
                          <span>
                            Nuclei Recall:{" "}
                            {(b.metrics_json.recall.nuclei * 100).toFixed(1)}%
                          </span>
                          <span>
                            Combined Recall:{" "}
                            {(b.metrics_json.recall.all_engines * 100).toFixed(1)}%
                          </span>
                        </div>
                        <div className="mt-1 text-zinc-400">
                          AI Unique True Positives:{" "}
                          {b.metrics_json.ai_unique_true_positives.join(", ") ||
                            "none"}{" "}
                          • Provenance: {b.data_provenance}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}
          </div>
        );
      }}
    </OrgShell>
  );
}
