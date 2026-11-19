"use client";

import { useParams, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  FileWarning,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import OrgShell, {
  hasPermission,
  useOrgWorkspaceContext,
} from "@/components/OrgShell";
import { Badge, SeverityBadge, StatusBadge } from "@/components/ui/Badge";
import { Panel, SectionHeader } from "@/components/ui/Card";
import { PageHeader } from "@/components/ui/PageHeader";
import { Select } from "@/components/ui/Select";
import { EmptyState, NoticeBanner } from "@/components/ui/States";
import { DataTableWrapper, Td, Th } from "@/components/ui/Table";
import { apiFetch, formatUtc } from "@/lib/api";
import type {
  AuthMe,
  FindingDetailItem,
  FindingEventItem,
  FindingItem,
  PaginatedResponse,
  RiskExceptionItem,
  ScannerCoverageResponse,
} from "@/lib/types";

function FindingsContent({ orgId, auth }: { orgId: string; auth: AuthMe }) {
  const searchParams = useSearchParams();
  const scanRunFilter = searchParams.get("scan_run_id");
  const initialPurl = searchParams.get("purl") || "";
  const initialSeverity = searchParams.get("severity") || "";

  const workspaceCtx = useOrgWorkspaceContext();
  const selectedProjectId = workspaceCtx?.selectedProjectId ?? "all";

  const [activeTab, setActiveTab] = useState<"findings" | "exceptions">(
    "findings",
  );
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [exceptions, setExceptions] = useState<RiskExceptionItem[]>([]);
  const [exceptionsTotal, setExceptionsTotal] = useState(0);
  const [total, setTotal] = useState(0);
  const [categoryFilter, setCategoryFilter] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<string>(initialSeverity);
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [purlFilter, setPurlFilter] = useState<string>(initialPurl);
  const [exceptionStatusFilter, setExceptionStatusFilter] =
    useState<string>("");

  const [selected, setSelected] = useState<FindingDetailItem | null>(null);
  const [events, setEvents] = useState<FindingEventItem[]>([]);
  const [coverage, setCoverage] = useState<ScannerCoverageResponse | null>(
    null,
  );
  const [loading, setLoading] = useState(true);
  const [evaluatingSla, setEvaluatingSla] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Triage state
  const [triageStatus, setTriageStatus] = useState<string>("open");
  const [triagePriority, setTriagePriority] = useState<string>("medium");
  const [triageNotes, setTriageNotes] = useState<string>("");
  const [triageAssigned, setTriageAssigned] = useState<string>("");

  // Request exception state
  const [showExceptionForm, setShowExceptionForm] = useState(false);
  const [exceptionReason, setExceptionReason] = useState("");
  const [exceptionControls, setExceptionControls] = useState("");
  const [exceptionDays, setExceptionDays] = useState(30);

  // Review exception state
  const [reviewingId, setReviewingId] = useState<string | null>(null);
  const [reviewNotes, setReviewNotes] = useState<string>("");

  const membership =
    auth.memberships.find((m) => m.organization_id === orgId) || null;
  const canTriage = hasPermission(membership, "finding:triage");
  const canRequestException = hasPermission(
    membership,
    "risk_exception:request",
  );
  const canApproveException = hasPermission(
    membership,
    "risk_exception:approve",
  );

  const loadData = useCallback(async () => {
    try {
      const qs = new URLSearchParams();
      if (selectedProjectId !== "all") qs.set("project_id", selectedProjectId);
      if (scanRunFilter) qs.set("scan_run_id", scanRunFilter);
      if (categoryFilter) qs.set("category", categoryFilter);
      if (severityFilter) qs.set("severity", severityFilter);
      if (statusFilter) qs.set("status", statusFilter);
      if (purlFilter.trim()) qs.set("purl", purlFilter.trim());
      const querySuffix = qs.toString() ? `?${qs.toString()}` : "";

      const excQs = new URLSearchParams();
      if (selectedProjectId !== "all") excQs.set("project_id", selectedProjectId);
      if (exceptionStatusFilter) excQs.set("status", exceptionStatusFilter);
      const excSuffix = excQs.toString() ? `?${excQs.toString()}` : "";

      const [findingPage, cov, excPage] = await Promise.all([
        apiFetch<PaginatedResponse<FindingItem>>(
          `/api/v1/organizations/${orgId}/findings${querySuffix}`,
        ),
        apiFetch<ScannerCoverageResponse>(
          `/api/v1/organizations/${orgId}/scanner-coverage`,
        ).catch(() => null),
        apiFetch<PaginatedResponse<RiskExceptionItem>>(
          `/api/v1/organizations/${orgId}/risk-exceptions${excSuffix}`,
        ).catch(() => ({ items: [] as RiskExceptionItem[], total: 0 })),
      ]);
      setFindings(findingPage.items);
      setTotal(findingPage.total);
      setCoverage(cov);
      setExceptions(excPage.items);
      setExceptionsTotal(excPage.total);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load findings");
    } finally {
      setLoading(false);
    }
  }, [
    orgId,
    selectedProjectId,
    scanRunFilter,
    categoryFilter,
    severityFilter,
    statusFilter,
    purlFilter,
    exceptionStatusFilter,
  ]);

  useEffect(() => {
    let active = true;
    void Promise.resolve().then(() => {
      if (active) return loadData();
    });
    return () => {
      active = false;
    };
  }, [loadData]);

  const inspectFinding = async (findingId: string) => {
    try {
      const [detail, eventList] = await Promise.all([
        apiFetch<FindingDetailItem>(
          `/api/v1/organizations/${orgId}/findings/${findingId}`,
        ),
        apiFetch<FindingEventItem[]>(
          `/api/v1/organizations/${orgId}/findings/${findingId}/events`,
        ).catch(() => []),
      ]);
      setSelected(detail);
      setEvents(eventList);
      setTriageStatus(detail.status);
      setTriagePriority(detail.business_priority || "medium");
      setTriageNotes(detail.remediation_notes || "");
      setTriageAssigned(detail.assigned_to || "");
      setShowExceptionForm(false);
      setError(null);
      setActionSuccess(null);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to load finding details",
      );
    }
  };

  const handleEvaluateSla = async () => {
    setEvaluatingSla(true);
    setError(null);
    setActionSuccess(null);
    try {
      const res = await apiFetch<{ breached_count: number }>(
        `/api/v1/organizations/${orgId}/findings/evaluate-sla`,
        {
          method: "POST",
          csrfToken: auth.csrf_token,
        },
      );
      setActionSuccess(
        `SLA evaluation complete: ${res.breached_count} finding(s) transitioned to SLA breached.`,
      );
      await loadData();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to evaluate SLA breaches",
      );
    } finally {
      setEvaluatingSla(false);
    }
  };

  const handleUpdateTriage = async () => {
    if (!selected) return;
    try {
      const updated = await apiFetch<FindingDetailItem>(
        `/api/v1/organizations/${orgId}/findings/${selected.id}`,
        {
          method: "PATCH",
          csrfToken: auth.csrf_token,
          body: JSON.stringify({
            status: triageStatus,
            business_priority: triagePriority,
            assigned_to: triageAssigned.trim() || null,
            remediation_notes: triageNotes.trim() || null,
          }),
        },
      );
      setSelected(updated);
      setActionSuccess("Triage updated successfully.");
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update triage");
    }
  };

  const handleRequestRetest = async () => {
    if (!selected) return;
    try {
      await apiFetch<FindingDetailItem>(
        `/api/v1/organizations/${orgId}/findings/${selected.id}`,
        {
          method: "PATCH",
          csrfToken: auth.csrf_token,
          body: JSON.stringify({
            retest_status: "pending_retest",
            comment: "Retest requested via web UI",
          }),
        },
      );
      setActionSuccess("Retest queued successfully.");
      await inspectFinding(selected.id);
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to request retest");
    }
  };

  const handleRequestException = async () => {
    if (!selected) return;
    const expiresAt = new Date(
      Date.now() + Math.max(1, Math.min(90, exceptionDays)) * 86_400_000,
    ).toISOString();
    try {
      await apiFetch(
        `/api/v1/organizations/${orgId}/findings/${selected.id}/risk-exceptions`,
        {
          method: "POST",
          csrfToken: auth.csrf_token,
          body: JSON.stringify({
            reason: exceptionReason.trim(),
            mitigating_controls: exceptionControls.trim(),
            expires_at: expiresAt,
          }),
        },
      );
      setActionSuccess("Risk exception requested successfully.");
      setShowExceptionForm(false);
      setExceptionReason("");
      setExceptionControls("");
      await inspectFinding(selected.id);
      await loadData();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to request risk exception",
      );
    }
  };

  const handleReviewException = async (
    exceptionId: string,
    approved: boolean,
  ) => {
    setError(null);
    setActionSuccess(null);
    try {
      await apiFetch(
        `/api/v1/organizations/${orgId}/risk-exceptions/${exceptionId}/review`,
        {
          method: "POST",
          csrfToken: auth.csrf_token,
          body: JSON.stringify({
            approved,
            review_notes:
              reviewNotes.trim() ||
              (approved
                ? "Approved via Security Exceptions Queue"
                : "Rejected via Security Exceptions Queue"),
          }),
        },
      );
      setReviewingId(null);
      setReviewNotes("");
      setActionSuccess(
        approved
          ? "Risk exception approved and linked finding marked risk_accepted."
          : "Risk exception rejected.",
      );
      await loadData();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to review risk exception",
      );
    }
  };

  const pendingExceptionsCount = exceptions.filter(
    (e) => e.status === "pending",
  ).length;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Vulnerability Management"
        title="Canonical Findings & Risk Exceptions"
        description={`Deduplicated findings across SAST, Secrets, SCA, Container, IaC, and Exploit Validation (${total} matching${
          scanRunFilter ? `, scan ${scanRunFilter.slice(0, 8)}` : ""
        }).`}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {canTriage && (
              <button
                type="button"
                onClick={() => void handleEvaluateSla()}
                disabled={evaluatingSla}
                className="vf-btn-warning h-8 px-3.5 text-xs"
              >
                <Clock className="h-3.5 w-3.5" />
                {evaluatingSla ? "Evaluating..." : "Evaluate SLA Breaches"}
              </button>
            )}
            <button
              type="button"
              onClick={() => {
                setLoading(true);
                void loadData();
              }}
              className="vf-btn-secondary h-8 px-3.5 text-xs"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Refresh
            </button>
          </div>
        }
      />

      {/* Tabs */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.068] pb-3">
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setActiveTab("findings")}
            className={`inline-flex items-center gap-2 rounded-full border px-3.5 py-1.5 text-xs font-medium transition ${
              activeTab === "findings"
                ? "border-white/[0.14] bg-[#1c1c22] text-white"
                : "border-transparent text-zinc-400 hover:bg-white/[0.04] hover:text-zinc-200"
            }`}
          >
            <ShieldAlert className="h-3.5 w-3.5" />
            Canonical Findings
            <Badge tone="neutral">{total}</Badge>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("exceptions")}
            className={`inline-flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
              activeTab === "exceptions"
                ? "bg-[#19191f] text-amber-300 border border-white/[0.08]"
                : "text-zinc-400 hover:bg-[#141417] hover:text-zinc-200"
            }`}
          >
            <FileWarning className="h-3.5 w-3.5" />
            Risk Exceptions Queue
            <Badge tone={pendingExceptionsCount > 0 ? "warning" : "neutral"}>
              {pendingExceptionsCount} pending / {exceptionsTotal}
            </Badge>
          </button>
        </div>

        {activeTab === "findings" ? (
          <div className="flex flex-wrap gap-2 text-xs">
            <input
              type="text"
              value={purlFilter}
              onChange={(e) => setPurlFilter(e.target.value)}
              placeholder="Filter by PURL..."
              className="w-40 rounded-lg border border-white/[0.1] bg-[#111114] px-2.5 py-1.5 text-zinc-200 placeholder:text-zinc-500 focus:border-white/[0.08] focus:outline-none"
            />
            <div className="w-36">
              <Select
                aria-label="Filter by category"
                size="sm"
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
              >
                <option value="">All categories</option>
                <option value="sast">SAST</option>
                <option value="secrets">Secrets</option>
                <option value="sca">SCA</option>
                <option value="sbom">SBOM</option>
                <option value="container">Container</option>
                <option value="iac">IaC</option>
                <option value="dast">DAST</option>
              </Select>
            </div>
            <div className="w-36">
              <Select
                aria-label="Filter by severity"
                size="sm"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
              >
                <option value="">All severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </Select>
            </div>
            <div className="w-36">
              <Select
                aria-label="Filter by status"
                size="sm"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
              >
                <option value="">All statuses</option>
                <option value="open">Open</option>
                <option value="in_progress">In Progress</option>
                <option value="resolved">Resolved</option>
                <option value="risk_accepted">Risk Accepted</option>
                <option value="false_positive">False Positive</option>
              </Select>
            </div>
          </div>
        ) : (
          <div className="flex items-center gap-2 text-xs">
            <div className="w-44">
              <Select
                aria-label="Filter exception status"
                size="sm"
                value={exceptionStatusFilter}
                onChange={(e) => setExceptionStatusFilter(e.target.value)}
              >
                <option value="">All exception states</option>
                <option value="pending">Pending Review</option>
                <option value="approved">Approved</option>
                <option value="rejected">Rejected</option>
                <option value="expired">Expired</option>
              </Select>
            </div>
          </div>
        )}
      </div>

      {error && <NoticeBanner tone="error" message={error} />}
      {actionSuccess && <NoticeBanner tone="success" message={actionSuccess} />}

      {activeTab === "findings" ? (
        <>
          {loading ? (
            <div className="h-48 animate-pulse rounded-xl border border-white/[0.068] bg-[#141417]" />
          ) : findings.length === 0 ? (
            <EmptyState
              icon={<ShieldCheck className="h-5 w-5 text-zinc-200" />}
              title="No canonical findings match the active filter"
              description="Adjust filters or run authorized assessments from the Scan Center to populate deduplicated findings."
            />
          ) : (
            <DataTableWrapper>
              <table className="min-w-full text-left text-xs">
                <thead>
                  <tr>
                    <Th>Severity / Priority</Th>
                    <Th>Status / SLA</Th>
                    <Th>Category / Tool</Th>
                    <Th>Rule &amp; Title</Th>
                    <Th>Location</Th>
                    <Th>Retest</Th>
                    <Th>Occurrences</Th>
                    <Th className="text-right">Action</Th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.06]/80 text-zinc-300">
                  {findings.map((f) => (
                    <tr key={f.id} className="hover:bg-white/[0.03]">
                      <Td>
                        <div className="flex flex-wrap items-center gap-1.5">
                          <SeverityBadge severity={f.severity} />
                          {f.business_priority && (
                            <Badge tone="neutral">{f.business_priority}</Badge>
                          )}
                          {f.is_known_exploited && (
                            <Badge tone="danger">KEV</Badge>
                          )}
                        </div>
                      </Td>
                      <Td>
                        <div className="space-y-1">
                          <StatusBadge status={f.status} />
                          {f.sla_breached ? (
                            <div className="inline-flex items-center gap-1 rounded border border-white/[0.08] bg-[#131317] px-1.5 py-0.5 text-[10px] font-semibold text-rose-300">
                              <AlertTriangle className="h-2.5 w-2.5" />
                              SLA BREACHED
                            </div>
                          ) : f.sla_due_at ? (
                            <div className="text-[11px] text-zinc-400">
                              Due {formatUtc(f.sla_due_at).slice(0, 10)}
                            </div>
                          ) : null}
                        </div>
                      </Td>
                      <Td className="font-mono text-zinc-300">
                        {f.category} / {f.scanner_tool_id}
                      </Td>
                      <Td>
                        <div className="font-medium text-white">{f.title}</div>
                        <div className="font-mono text-[11px] text-zinc-400">
                          {f.rule_id}
                        </div>
                        {f.purl && (
                          <div className="mt-0.5 font-mono text-[11px] text-[#93c5fd]">
                            {f.purl}
                            {f.fixed_version ? ` (fix: ${f.fixed_version})` : ""}
                          </div>
                        )}
                        {f.cwe_ids.length > 0 && (
                          <div className="mt-1 flex flex-wrap gap-1">
                            {f.cwe_ids.map((cwe) => (
                              <span
                                key={cwe}
                                className="rounded bg-[#1c1c20] px-1.5 py-0.5 text-[10px] text-zinc-200"
                              >
                                {cwe}
                              </span>
                            ))}
                          </div>
                        )}
                      </Td>
                      <Td className="font-mono text-zinc-400">
                        {f.file_path || "-"}
                        {f.start_line ? `:${f.start_line}` : ""}
                      </Td>
                      <Td>
                        {f.retest_status && f.retest_status !== "none" ? (
                          <StatusBadge status={f.retest_status} />
                        ) : (
                          <span className="text-zinc-500">—</span>
                        )}
                      </Td>
                      <Td className="font-mono">{f.occurrence_count}</Td>
                      <Td className="text-right">
                        <button
                          type="button"
                          onClick={() => void inspectFinding(f.id)}
                          className="rounded-lg border border-white/[0.1] bg-[#111114] px-2.5 py-1 text-xs font-medium text-zinc-200 transition hover:bg-white/[0.06]"
                        >
                          Triage
                        </button>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </DataTableWrapper>
          )}

          {selected && (
            <Panel className="space-y-4 border-white/[0.1] bg-[#111114]/95">
              <div className="flex flex-wrap items-start justify-between gap-4 border-b border-white/[0.068] pb-4">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <h2 className="text-sm font-semibold text-white">
                      {selected.title}
                    </h2>
                    <SeverityBadge severity={selected.severity} />
                    {selected.sla_breached && (
                      <Badge tone="danger">SLA BREACHED</Badge>
                    )}
                  </div>
                  <p className="mt-1 font-mono text-[11px] text-zinc-400">
                    Fingerprint: {selected.fingerprint} · Rule: {selected.rule_id}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setSelected(null)}
                  className="vf-btn-secondary px-2.5 py-1 text-xs"
                >
                  Close
                </button>
              </div>

              {selected.description && (
                <p className="text-xs leading-relaxed text-zinc-300">
                  {selected.description}
                </p>
              )}

              <div className="grid grid-cols-1 gap-4 md:grid-cols-2 text-xs">
                <div className="rounded-lg border border-white/[0.068] bg-[#0e0e11] p-4 space-y-3">
                  <h3 className="font-semibold text-white">
                    Triage &amp; Lifecycle Management
                  </h3>
                  <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                    <div>
                      <label className="mb-1 block text-[11px] text-zinc-400">
                        Status
                      </label>
                      <Select
                        size="sm"
                        value={triageStatus}
                        onChange={(e) => setTriageStatus(e.target.value)}
                        disabled={!canTriage}
                      >
                        <option value="open">Open</option>
                        <option value="in_progress">In Progress</option>
                        <option value="resolved">Resolved</option>
                        <option value="risk_accepted">Risk Accepted</option>
                        <option value="false_positive">False Positive</option>
                      </Select>
                    </div>
                    <div>
                      <label className="mb-1 block text-[11px] text-zinc-400">
                        Business Priority
                      </label>
                      <Select
                        size="sm"
                        value={triagePriority}
                        onChange={(e) => setTriagePriority(e.target.value)}
                        disabled={!canTriage}
                      >
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                      </Select>
                    </div>
                  </div>
                  <div>
                    <label className="mb-1 block text-[11px] text-zinc-400">
                      Assignee User UUID (optional)
                    </label>
                    <input
                      type="text"
                      value={triageAssigned}
                      onChange={(e) => setTriageAssigned(e.target.value)}
                      disabled={!canTriage}
                      placeholder="User UUID"
                      className="w-full rounded border border-white/[0.1] bg-[#111114] px-2 py-1 text-zinc-200"
                    />
                  </div>
                  <div>
                    <label className="mb-1 block text-[11px] text-zinc-400">
                      Remediation Notes
                    </label>
                    <textarea
                      value={triageNotes}
                      onChange={(e) => setTriageNotes(e.target.value)}
                      disabled={!canTriage}
                      rows={2}
                      placeholder="Notes on fix or validation..."
                      className="w-full rounded border border-white/[0.1] bg-[#111114] px-2 py-1 text-zinc-200"
                    />
                  </div>
                  <div className="flex flex-wrap gap-2 pt-1">
                    {canTriage && (
                      <button
                        type="button"
                        onClick={() => void handleUpdateTriage()}
                        className="vf-btn-primary px-3 py-1 text-xs"
                      >
                        Save Triage
                      </button>
                    )}
                    {canTriage && (
                      <button
                        type="button"
                        onClick={() => void handleRequestRetest()}
                        className="vf-btn-secondary h-7 px-3 text-xs"
                      >
                        Queue Retest
                      </button>
                    )}
                    {canRequestException && !showExceptionForm && (
                      <button
                        type="button"
                        onClick={() => setShowExceptionForm(true)}
                        className="vf-btn-warning h-7 px-3 text-xs"
                      >
                        Request Risk Exception
                      </button>
                    )}
                  </div>
                </div>

                <div className="rounded-lg border border-white/[0.068] bg-[#0e0e11] p-4 space-y-2">
                  <h3 className="font-semibold text-white">
                    SLA &amp; Environmental Context
                  </h3>
                  <div className="space-y-1.5 text-[11px] text-zinc-300">
                    <div>
                      <span className="text-zinc-400">SLA Due Date: </span>
                      <span
                        className={
                          selected.sla_breached
                            ? "font-bold text-rose-400"
                            : "text-white"
                        }
                      >
                        {selected.sla_due_at
                          ? formatUtc(selected.sla_due_at)
                          : "No SLA set"}
                      </span>
                    </div>
                    <div>
                      <span className="text-zinc-400">CVSS: </span>
                      <span>
                        {selected.cvss_score
                          ? `${selected.cvss_score} (${selected.cvss_vector || ""})`
                          : "N/A"}
                      </span>
                    </div>
                    <div>
                      <span className="text-zinc-400">First Seen: </span>
                      <span>{formatUtc(selected.first_seen_at)}</span>
                    </div>
                    <div>
                      <span className="text-zinc-400">Last Seen: </span>
                      <span>{formatUtc(selected.last_seen_at)}</span>
                    </div>
                    {selected.purl && (
                      <div>
                        <span className="text-zinc-400">PURL: </span>
                        <span className="font-mono text-[#93c5fd]">
                          {selected.purl}
                        </span>
                      </div>
                    )}
                    {selected.cve_id && (
                      <div>
                        <span className="text-zinc-400">CVE: </span>
                        <span className="font-mono text-zinc-200">
                          {selected.cve_id}
                        </span>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {showExceptionForm && (
                <div className="rounded-lg border border-white/[0.08] bg-[#131317] p-4 space-y-3 text-xs">
                  <h3 className="font-semibold text-zinc-200">
                    Request Time-Bound Risk Exception
                  </h3>
                  <div>
                    <label className="mb-1 block text-[11px] text-amber-300">
                      Business Reason (min 10 chars)
                    </label>
                    <input
                      type="text"
                      value={exceptionReason}
                      onChange={(e) => setExceptionReason(e.target.value)}
                      placeholder="Explain why this finding requires a temporary exception..."
                      className="w-full rounded border border-white/[0.08] bg-[#101013] px-2.5 py-1.5 text-zinc-200"
                    />
                  </div>
                  <div>
                    <label className="mb-1 block text-[11px] text-amber-300">
                      Mitigating Controls (min 10 chars)
                    </label>
                    <input
                      type="text"
                      value={exceptionControls}
                      onChange={(e) => setExceptionControls(e.target.value)}
                      placeholder="Describe WAF rules, segmentation, or compensating controls..."
                      className="w-full rounded border border-white/[0.08] bg-[#101013] px-2.5 py-1.5 text-zinc-200"
                    />
                  </div>
                  <div>
                    <label className="mb-1 block text-[11px] text-amber-300">
                      Duration (Days, max 90)
                    </label>
                    <input
                      type="number"
                      min={1}
                      max={90}
                      value={exceptionDays}
                      onChange={(e) => setExceptionDays(Number(e.target.value))}
                      className="w-24 rounded border border-white/[0.08] bg-[#101013] px-2.5 py-1.5 text-zinc-200"
                    />
                  </div>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => void handleRequestException()}
                      className="vf-btn-warning h-8 px-3.5 text-xs"
                    >
                      Submit Exception Request
                    </button>
                    <button
                      type="button"
                      onClick={() => setShowExceptionForm(false)}
                      className="vf-btn-secondary h-8 px-3.5 text-xs"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}

              {selected.code_snippet_redacted && (
                <div>
                  <h3 className="mb-1 text-xs font-semibold text-zinc-300">
                    Code Snippet (Secret Redacted)
                  </h3>
                  <pre className="overflow-x-auto rounded-lg border border-white/[0.068] bg-[#0e0e11] p-3 font-mono text-[11px] text-zinc-200">
                    {selected.code_snippet_redacted}
                  </pre>
                </div>
              )}

              <div>
                <h3 className="text-xs font-semibold text-zinc-200">
                  Audit Trail &amp; Lifecycle Events ({events.length})
                </h3>
                {events.length === 0 ? (
                  <p className="mt-1 text-xs text-zinc-500">
                    No lifecycle events recorded yet.
                  </p>
                ) : (
                  <div className="mt-2 max-h-48 space-y-1.5 overflow-y-auto">
                    {events.map((ev) => (
                      <div
                        key={ev.id}
                        className="flex flex-wrap items-center justify-between rounded-lg border border-white/[0.068] bg-[#0e0e11] px-3 py-1.5 font-mono text-[11px]"
                      >
                        <span>
                          <strong className="uppercase text-white">
                            {ev.event_type}
                          </strong>
                          {(ev.previous_status || ev.old_status) && ev.new_status
                            ? ` (${ev.previous_status ?? ev.old_status} → ${ev.new_status})`
                            : ""}
                          {ev.comment ? ` — "${ev.comment}"` : ""}
                        </span>
                        <span className="text-zinc-400">
                          {formatUtc(ev.created_at)}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </Panel>
          )}
        </>
      ) : (
        /* Risk Exceptions Queue */
        <Panel>
          <SectionHeader
            title="Time-Bound Risk Exceptions Queue"
            description="Segregation of duties enforced: requesters cannot approve their own risk exceptions."
          />
          {exceptions.length === 0 ? (
            <EmptyState
              icon={<FileWarning className="h-5 w-5" />}
              title="No risk exception requests found"
              description="Exception requests submitted during finding triage appear here for Lead/Admin/Owner review."
            />
          ) : (
            <DataTableWrapper>
              <table className="min-w-full text-left text-xs">
                <thead>
                  <tr>
                    <Th>Status</Th>
                    <Th>Finding</Th>
                    <Th>Reason &amp; Mitigating Controls</Th>
                    <Th>Expires</Th>
                    <Th>Review Decision</Th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.06]/80 text-zinc-300">
                  {exceptions.map((exc) => {
                    const isSelfRequest = exc.requested_by === auth.user.id;
                    const isReviewing = reviewingId === exc.id;
                    return (
                      <tr key={exc.id} className="hover:bg-white/[0.03]">
                        <Td>
                          <StatusBadge status={exc.status} />
                        </Td>
                        <Td className="font-mono text-[#93c5fd]">
                          {exc.finding_id.slice(0, 8)}
                        </Td>
                        <Td className="max-w-md space-y-1">
                          <div className="text-white">{exc.reason}</div>
                          <div className="text-[11px] text-zinc-400">
                            Controls: {exc.mitigating_controls}
                          </div>
                          {exc.review_notes && (
                            <div className="text-[11px] text-zinc-400">
                              Review Notes: {exc.review_notes}
                            </div>
                          )}
                        </Td>
                        <Td className="whitespace-nowrap text-zinc-400">
                          {formatUtc(exc.expires_at)}
                        </Td>
                        <Td>
                          {exc.status !== "pending" ? (
                            <span className="text-zinc-500">Reviewed</span>
                          ) : !canApproveException ? (
                            <Badge tone="neutral">Requires Approver Role</Badge>
                          ) : isSelfRequest ? (
                            <Badge tone="warning">
                              Self-Approval Prohibited
                            </Badge>
                          ) : isReviewing ? (
                            <div className="space-y-2 min-w-[200px]">
                              <input
                                type="text"
                                value={reviewNotes}
                                onChange={(e) => setReviewNotes(e.target.value)}
                                placeholder="Decision justification..."
                                className="w-full rounded border border-white/[0.1] bg-[#0e0e11] px-2 py-1 text-xs text-white"
                              />
                              <div className="flex gap-1.5">
                                <button
                                  type="button"
                                  onClick={() =>
                                    void handleReviewException(exc.id, true)
                                  }
                                  className="inline-flex items-center gap-1 vf-btn-primary px-2.5 py-1 text-[11px]"
                                >
                                  <CheckCircle2 className="h-3 w-3" />
                                  Approve
                                </button>
                                <button
                                  type="button"
                                  onClick={() =>
                                    void handleReviewException(exc.id, false)
                                  }
                                  className="vf-btn-danger px-2 py-1 text-[11px] font-medium"
                                >
                                  <XCircle className="h-3 w-3" />
                                  Reject
                                </button>
                                <button
                                  type="button"
                                  onClick={() => setReviewingId(null)}
                                  className="vf-btn-secondary h-6 px-2.5 text-[11px]"
                                >
                                  Cancel
                                </button>
                              </div>
                            </div>
                          ) : (
                            <button
                              type="button"
                              onClick={() => {
                                setReviewingId(exc.id);
                                setReviewNotes("");
                              }}
                              className="vf-btn-warning px-2.5 py-1 text-xs font-medium"
                            >
                              Review Request
                            </button>
                          )}
                        </Td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </DataTableWrapper>
          )}
        </Panel>
      )}

      {coverage && (
        <Panel className="text-xs">
          <SectionHeader
            title={`Active Scanner Adapters & Coverage Registry (Phase ${coverage.phase})`}
            description="Languages marked partial or unsupported cause scans to report explicit partial coverage rather than synthetic clean passes."
          />
        </Panel>
      )}
    </div>
  );
}

export default function OrganizationFindingsPage() {
  const params = useParams<{ orgId: string }>();
  const orgId = params.orgId;

  return (
    <OrgShell orgId={orgId}>
      {({ auth, membership }) =>
        hasPermission(membership, "finding:read") ? (
          <Suspense
            fallback={
              <div className="h-48 animate-pulse rounded-xl border border-white/[0.068] bg-[#141417]" />
            }
          >
            <FindingsContent orgId={orgId} auth={auth} />
          </Suspense>
        ) : (
          <NoticeBanner
            tone="error"
            title="Permission Restricted"
            message="You do not have permission (finding:read) to view findings in this organization."
          />
        )
      }
    </OrgShell>
  );
}
