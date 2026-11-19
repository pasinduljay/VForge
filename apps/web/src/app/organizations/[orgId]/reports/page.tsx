"use client";

import { useParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useState } from "react";
import OrgShell, { hasPermission } from "@/components/OrgShell";
import { Select } from "@/components/ui/Select";
import { apiFetch, formatUtc } from "@/lib/api";
import type {
  AuthMe,
  PaginatedResponse,
  Project,
  ReportItem,
} from "@/lib/types";

const FORMAT_BADGE: Record<string, string> = {
  html: "border-white/[0.08] bg-[#1a1a1f] text-zinc-200",
  pdf: "border-white/[0.08] bg-[#131317] text-zinc-200",
  json: "border-white/[0.08] bg-[#1a1a1f] text-zinc-200",
  sarif: "border-purple-600 bg-purple-950/70 text-purple-200",
};

function ReportsContent({ orgId, auth }: { orgId: string; auth: AuthMe }) {
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Report generation form state
  const [showGenerateModal, setShowGenerateModal] = useState(false);
  const [reportTitle, setReportTitle] = useState("");
  const [reportType, setReportType] = useState<
    "executive" | "technical_vapt" | "compliance_summary" | "sarif_export"
  >("technical_vapt");
  const [reportFormat, setReportFormat] = useState<"html" | "pdf" | "json" | "sarif">("html");
  const [selectedProjectId, setSelectedProjectId] = useState<string>("");
  const [generating, setGenerating] = useState(false);

  const membership = auth.memberships.find((m) => m.organization_id === orgId) || null;
  const canGenerate = hasPermission(membership, "report:generate");

  const loadData = useCallback(async () => {
    try {
      const [reportPage, projectPage] = await Promise.all([
        apiFetch<PaginatedResponse<ReportItem>>(`/api/v1/organizations/${orgId}/reports`),
        apiFetch<PaginatedResponse<Project>>(`/api/v1/organizations/${orgId}/projects`).catch(
          () => ({ items: [], total: 0, limit: 50, offset: 0 }),
        ),
      ]);
      setReports(reportPage.items);
      setTotal(reportPage.total);
      setProjects(projectPage.items);
      if (projectPage.items.length > 0 && !selectedProjectId) {
        setSelectedProjectId(projectPage.items[0].id);
      }
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load reports");
    } finally {
      setLoading(false);
    }
  }, [orgId, selectedProjectId]);

  useEffect(() => {
    let active = true;
    const run = async () => {
      if (active) {
        await loadData();
      }
    };
    void run();
    return () => {
      active = false;
    };
  }, [loadData]);

  useEffect(() => {
    if (!showGenerateModal) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (
        e.key === "Escape" &&
        !generating &&
        !document.querySelector('[role="listbox"]')
      ) {
        setShowGenerateModal(false);
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [showGenerateModal, generating]);

  const handleGenerateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!reportTitle.trim()) {
      setError("Report title is required");
      return;
    }
    if (!selectedProjectId) {
      setError("Please select a project");
      return;
    }
    setGenerating(true);
    setError(null);
    setSuccess(null);
    try {
      await apiFetch<ReportItem>(`/api/v1/organizations/${orgId}/reports`, {
        method: "POST",
        csrfToken: auth.csrf_token,
        body: JSON.stringify({
          title: reportTitle.trim(),
          report_type: reportType,
          format: reportFormat,
          project_id: selectedProjectId,
        }),
      });
      setSuccess("Report generated successfully with AES-256-GCM encrypted artifact.");
      setShowGenerateModal(false);
      setReportTitle("");
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Report generation failed");
    } finally {
      setGenerating(false);
    }
  };

  const handleDownload = async (report: ReportItem) => {
    try {
      const res = await fetch(`/api/v1/organizations/${orgId}/reports/${report.id}/download`, {
        method: "GET",
        headers: {
          Accept: "application/octet-stream",
        },
      });
      if (!res.ok) {
        throw new Error(`Download failed with status ${res.status}`);
      }
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const ext = report.format === "sarif" ? "sarif.json" : report.format;
      a.download = `${report.title.toLowerCase().replace(/[^a-z0-9_-]/g, "_")}_${report.id.slice(0, 8)}.${ext}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to download report");
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="mb-1 text-[11px] font-semibold uppercase tracking-[0.12em] text-blue-400">
            Step 6 of 6 · Export &amp; Share
          </div>
          <h1 className="text-xl font-semibold text-white">Security &amp; Audit Reports</h1>
          <p className="text-xs text-zinc-400">
            Export summary and technical reports in HTML, PDF, JSON, or SARIF with encrypted artifact storage ({total} total).
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => {
              setLoading(true);
              void loadData();
            }}
            className="vf-btn-secondary h-8 px-3.5 text-xs"
          >
            Refresh
          </button>
          {canGenerate && (
            <button
              type="button"
              onClick={() => setShowGenerateModal(true)}
              className="vf-btn-primary h-8 px-4 text-xs"
            >
              + Generate Report
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="rounded border border-white/[0.08] bg-[#131317] px-4 py-2 text-xs text-zinc-200">
          {error}
        </div>
      )}

      {success && (
        <div className="rounded border border-white/[0.08] bg-[#121614] px-4 py-2 text-xs text-zinc-200">
          {success}
        </div>
      )}

      {loading ? (
        <div className="text-xs text-zinc-400">Loading reports...</div>
      ) : reports.length === 0 ? (
        <div className="rounded-lg border border-white/[0.068] bg-[#141417] p-8 text-center text-xs text-zinc-400">
          No reports generated yet. Click &quot;Generate Report&quot; to export your first security summary.
        </div>
      ) : (
        <div className="rounded-lg border border-white/[0.068] bg-[#141417] overflow-x-auto">
          <table className="min-w-full text-left text-xs">
            <thead className="border-b border-white/[0.068] uppercase text-zinc-400">
              <tr>
                <th className="px-4 py-3">Format</th>
                <th className="px-4 py-3">Report Title &amp; Type</th>
                <th className="px-4 py-3">Findings</th>
                <th className="px-4 py-3">Artifact ID</th>
                <th className="px-4 py-3">Generated At</th>
                <th className="px-4 py-3">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06] text-zinc-300">
              {reports.map((rep) => (
                <tr key={rep.id} className="hover:bg-white/[0.06]/40">
                  <td className="px-4 py-3">
                    <span
                      className={`inline-block rounded border px-2 py-0.5 uppercase font-mono text-[10px] ${
                        FORMAT_BADGE[rep.format] || "border-white/[0.08]"
                      }`}
                    >
                      {rep.format}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="font-medium text-white">{rep.title}</div>
                    <div className="text-[11px] text-zinc-400 font-mono">
                      {rep.report_type.replace(/_/g, " ")}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-zinc-300">
                    {typeof rep.summary?.total_findings === "number"
                      ? `${rep.summary.total_findings} finding${rep.summary.total_findings === 1 ? "" : "s"}`
                      : "Encrypted"}
                  </td>
                  <td className="px-4 py-3 font-mono text-[11px] text-zinc-400">
                    {rep.artifact_id ? `${rep.artifact_id.slice(0, 12)}...` : "-"}
                  </td>
                  <td className="px-4 py-3 text-zinc-400">
                    {formatUtc(rep.created_at)}
                  </td>
                  <td className="px-4 py-3">
                    {rep.artifact_id ? (
                      <button
                        type="button"
                        onClick={() => void handleDownload(rep)}
                        className="vf-btn-secondary h-7 px-3 text-xs"
                      >
                        Download
                      </button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showGenerateModal && (
        <div
          onClick={(e) => {
            if (e.target === e.currentTarget && !generating) {
              setShowGenerateModal(false);
            }
          }}
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-xs"
        >
          <div className="w-full max-w-md rounded-2xl border border-white/[0.09] bg-[#141418] p-6 space-y-4 text-xs shadow-2xl">
            <h2 className="text-sm font-semibold text-white">Generate Multi-Format Security Report</h2>
            <form onSubmit={handleGenerateReport} className="space-y-3">
              <div>
                <label className="block text-[11px] text-zinc-400 mb-1">Project Target</label>
                <Select
                  size="sm"
                  value={selectedProjectId}
                  onChange={(e) => setSelectedProjectId(e.target.value)}
                  required
                >
                  {projects.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} ({p.slug})
                    </option>
                  ))}
                </Select>
              </div>

              <div>
                <label className="block text-[11px] text-zinc-400 mb-1">Report Title</label>
                <input
                  type="text"
                  value={reportTitle}
                  onChange={(e) => setReportTitle(e.target.value)}
                  placeholder="e.g. Q4 Executive Vulnerability Summary"
                  className="vf-input text-xs"
                  required
                />
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div>
                  <label className="block text-[11px] text-zinc-400 mb-1">Report Type</label>
                  <Select
                    size="sm"
                    value={reportType}
                    onChange={(e) =>
                      setReportType(
                        e.target.value as
                          | "executive"
                          | "technical_vapt"
                          | "compliance_summary"
                          | "sarif_export",
                      )
                    }
                  >
                    <option value="technical_vapt">Technical VAPT</option>
                    <option value="executive">Executive Summary</option>
                    <option value="compliance_summary">Compliance Summary</option>
                    <option value="sarif_export">SARIF Export</option>
                  </Select>
                </div>

                <div>
                  <label className="block text-[11px] text-zinc-400 mb-1">Format</label>
                  <Select
                    size="sm"
                    value={reportFormat}
                    onChange={(e) =>
                      setReportFormat(e.target.value as "html" | "pdf" | "json" | "sarif")
                    }
                  >
                    <option value="html">HTML</option>
                    <option value="pdf">PDF (1.4 Binary)</option>
                    <option value="json">JSON</option>
                    <option value="sarif">SARIF 2.1.0</option>
                  </Select>
                </div>
              </div>

              <div className="rounded border border-white/[0.068] bg-[#0e0e11]/80 p-3 text-[11px] text-zinc-400">
                Generated reports are stored as AES-256-GCM envelope encrypted artifacts with tenant-isolated key derivation and decrypted on authenticated streaming download.
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowGenerateModal(false)}
                  disabled={generating}
                  className="vf-btn-secondary h-8 px-3.5 text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={generating}
                  className="vf-btn-primary h-8 px-4 text-xs"
                >
                  {generating ? "Generating..." : "Generate & Encrypt"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default function OrganizationReportsPage() {
  const params = useParams<{ orgId: string }>();
  const orgId = params.orgId;

  return (
    <OrgShell orgId={orgId}>
      {({ auth, membership }) =>
        hasPermission(membership, "report:read") ? (
          <Suspense fallback={<div className="text-xs text-zinc-400">Loading reports...</div>}>
            <ReportsContent orgId={orgId} auth={auth} />
          </Suspense>
        ) : (
          <div className="rounded border border-white/[0.08] bg-[#131317] p-4 text-xs text-zinc-200">
            You do not have permission (report:read) to view reports in this organization.
          </div>
        )
      }
    </OrgShell>
  );
}
