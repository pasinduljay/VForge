"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  Check,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ChevronUp,
  Copy,
  Database,
  ExternalLink,
  Flame,
  Globe,
  Radar,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  TrendingUp,
  X,
} from "lucide-react";
import OrgShell from "@/components/OrgShell";
import { Badge, SeverityBadge, StatusBadge } from "@/components/ui/Badge";
import { Panel, SectionHeader, StatCard } from "@/components/ui/Card";
import { PageHeader } from "@/components/ui/PageHeader";
import { Select } from "@/components/ui/Select";
import { EmptyState, NoticeBanner } from "@/components/ui/States";
import { DataTableWrapper, Td, Th } from "@/components/ui/Table";
import { apiFetch, formatUtc } from "@/lib/api";
import type {
  CveThreatIntelOut,
  ExposureFindingImportResponse,
  ExposureQueryType,
  ExposureRecordItem,
  ExposureSearchResponse,
  IntelEnrichmentResponse,
  IntelSourceItem,
  IntelSyncRunItem,
  OrgThreatIntelSummary,
  PaginatedResponse,
  Project,
} from "@/lib/types";

type WorkspaceTab = "osint" | "cve" | "sources";
type ExposureSortMode = "priority" | "newest";

const CATEGORY_LABEL: Record<string, string> = {
  infostealer_infection: "Infostealer",
  compromised_endpoint: "Compromised Portal",
  credential_breach: "Credential Breach",
  network_exposure: "Network / CVE",
  attack_surface_url: "Attack Surface",
};

const SEVERITY_ORDER: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

const PAGE_SIZE = 10;

const EXAMPLE_QUERIES: { label: string; query: string; type: ExposureQueryType }[] = [
  { label: "example.com", query: "example.com", type: "domain" },
  { label: "@example.com", query: "@example.com", type: "auto" },
  { label: "example corp", query: "example corp", type: "company" },
  { label: "admin@example.com", query: "admin@example.com", type: "email" },
  { label: "93.184.216.34", query: "93.184.216.34", type: "ip" },
];

function formatSourceType(raw: string): string {
  return raw.replaceAll("_", " ");
}

function ThreatIntelContent({ orgId }: { orgId: string }) {
  const [activeTab, setActiveTab] = useState<WorkspaceTab>("osint");

  const [sources, setSources] = useState<IntelSourceItem[]>([]);
  const [summary, setSummary] = useState<OrgThreatIntelSummary | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [actionTone, setActionTone] = useState<"success" | "error" | "info">("success");
  const [syncingSlug, setSyncingSlug] = useState<string | null>(null);
  const [enriching, setEnriching] = useState(false);

  // Multi-source Compromise & OSINT Exposure Search state
  const [exposureQuery, setExposureQuery] = useState("");
  const [exposureQueryType, setExposureQueryType] = useState<ExposureQueryType>("auto");
  const [exposureResult, setExposureResult] = useState<ExposureSearchResponse | null>(null);
  const [exposureLoading, setExposureLoading] = useState(false);
  const [exposureError, setExposureError] = useState<string | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [localFilterText, setLocalFilterText] = useState<string>("");
  const [sortMode, setSortMode] = useState<ExposureSortMode>("priority");
  const [page, setPage] = useState<number>(1);
  const [expandedRecords, setExpandedRecords] = useState<Record<string, boolean>>({});
  const [showAllSubdomains, setShowAllSubdomains] = useState(false);
  const [showProvenance, setShowProvenance] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [importingRecordId, setImportingRecordId] = useState<string | null>(null);
  const [importedRecordIds, setImportedRecordIds] = useState<Record<string, string>>({});

  // CVE Lookup state
  const [cveSearch, setCveSearch] = useState("CVE-2021-44228");
  const [cveIntel, setCveIntel] = useState<CveThreatIntelOut | null>(null);
  const [cveLoading, setCveLoading] = useState(false);
  const [cveError, setCveError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    try {
      const [sourcesRes, summaryRes, projectsRes] = await Promise.allSettled([
        apiFetch<IntelSourceItem[]>("/api/v1/intel/sources"),
        apiFetch<OrgThreatIntelSummary>(`/api/v1/organizations/${orgId}/intel/summary`),
        apiFetch<PaginatedResponse<Project>>(`/api/v1/organizations/${orgId}/projects`),
      ]);

      if (sourcesRes.status === "fulfilled") {
        setSources(sourcesRes.value);
      } else {
        throw sourcesRes.reason;
      }

      if (summaryRes.status === "fulfilled") {
        setSummary(summaryRes.value);
      }

      if (projectsRes.status === "fulfilled") {
        setProjects(projectsRes.value.items);
        if (projectsRes.value.items.length > 0) {
          setSelectedProjectId((prev) => prev || projectsRes.value.items[0].id);
        }
      }

      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load threat intelligence catalog");
    } finally {
      setLoading(false);
    }
  }, [orgId]);

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

  const runExposureSearch = useCallback(
    async (queryOverride?: string, typeOverride?: ExposureQueryType) => {
      const q = (queryOverride ?? exposureQuery).trim();
      const t = typeOverride ?? exposureQueryType;
      if (!q) return;

      setExposureLoading(true);
      setExposureError(null);
      try {
        const res = await apiFetch<ExposureSearchResponse>(
          `/api/v1/organizations/${orgId}/intel/exposure-search`,
          {
            method: "POST",
            body: JSON.stringify({
              query: q,
              query_type: t,
            }),
          },
        );
        setExposureResult(res);
        setCategoryFilter("all");
        setLocalFilterText("");
        setPage(1);
        setExpandedRecords({});
        setShowAllSubdomains(false);
      } catch (err) {
        setExposureError(
          err instanceof Error ? err.message : `Exposure search failed for '${q}'`,
        );
      } finally {
        setExposureLoading(false);
      }
    },
    [exposureQuery, exposureQueryType, orgId],
  );

  const handleExposureSubmit = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    await runExposureSearch();
  };

  const handleQuickPreset = (presetQuery: string, presetType: ExposureQueryType = "auto") => {
    setExposureQuery(presetQuery);
    setExposureQueryType(presetType);
    void runExposureSearch(presetQuery, presetType);
  };

  const handleCopyText = async (id: string, value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedId(id);
      setTimeout(() => {
        setCopiedId((prev) => (prev === id ? null : prev));
      }, 1500);
    } catch {
      // Clipboard unavailable in insecure context
    }
  };

  const toggleExpandRecord = (recordId: string) => {
    setExpandedRecords((prev) => ({ ...prev, [recordId]: !prev[recordId] }));
  };

  const handleImportAsFinding = async (rec: ExposureRecordItem) => {
    if (!selectedProjectId) {
      setActionTone("error");
      setActionMessage("Create or select a Project first to track this exposure as a finding.");
      return;
    }
    setImportingRecordId(rec.record_id);
    setActionMessage(null);
    try {
      const res = await apiFetch<ExposureFindingImportResponse>(
        `/api/v1/organizations/${orgId}/intel/exposure-findings`,
        {
          method: "POST",
          body: JSON.stringify({
            project_id: selectedProjectId,
            source_slug: rec.source_slug,
            category: rec.category,
            severity: rec.severity,
            title: rec.title,
            target: rec.target,
            summary: rec.summary,
            remediation: rec.remediation || null,
            cve_id: rec.cve_id || null,
          }),
        },
      );
      setImportedRecordIds((prev) => ({ ...prev, [rec.record_id]: res.finding_id }));
      setActionTone("success");
      setActionMessage(`${res.message} (${res.title})`);
      await loadData();
    } catch (err) {
      setActionTone("error");
      setActionMessage(
        `Failed to import finding: ${err instanceof Error ? err.message : "Unknown error"}`,
      );
    } finally {
      setImportingRecordId(null);
    }
  };

  const handleSyncSource = async (slug: string) => {
    setSyncingSlug(slug);
    setActionMessage(null);
    try {
      const res = await apiFetch<IntelSyncRunItem>(
        `/api/v1/organizations/${orgId}/intel/sources/${slug}/sync`,
        { method: "POST" },
      );
      setActionTone(res.status === "failed" ? "error" : "success");
      setActionMessage(
        `Synchronized ${slug}: fetched ${res.records_fetched} records, persisted ${res.records_persisted}. Status: ${res.status}`,
      );
      await loadData();
    } catch (err) {
      setActionTone("error");
      setActionMessage(
        `Sync failed for ${slug}: ${err instanceof Error ? err.message : "Unknown error"}`,
      );
    } finally {
      setSyncingSlug(null);
    }
  };

  const handleBatchEnrich = async () => {
    setEnriching(true);
    setActionMessage(null);
    try {
      const res = await apiFetch<IntelEnrichmentResponse>(
        `/api/v1/organizations/${orgId}/findings/enrich`,
        {
          method: "POST",
          body: JSON.stringify({}),
        },
      );
      setActionTone("success");
      setActionMessage(res.message);
      await loadData();
    } catch (err) {
      setActionTone("error");
      setActionMessage(
        `Enrichment failed: ${err instanceof Error ? err.message : "Unknown error"}`,
      );
    } finally {
      setEnriching(false);
    }
  };

  const handleCveLookup = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const query = cveSearch.trim().toUpperCase();
    if (!query) return;

    setCveLoading(true);
    setCveError(null);
    try {
      const res = await apiFetch<CveThreatIntelOut>(`/api/v1/intel/cve/${query}`);
      setCveIntel(res);
    } catch (err) {
      setCveIntel(null);
      setCveError(err instanceof Error ? err.message : `CVE lookup failed for ${query}`);
    } finally {
      setCveLoading(false);
    }
  };

  const categoryCounts = useMemo(() => {
    const recs = exposureResult?.records || [];
    return {
      all: recs.length,
      credentials: recs.filter(
        (r) => r.category === "infostealer_infection" || r.category === "credential_breach",
      ).length,
      endpoints: recs.filter((r) => r.category === "compromised_endpoint").length,
      network: recs.filter((r) => r.category === "network_exposure").length,
      surface: recs.filter((r) => r.category === "attack_surface_url").length,
    };
  }, [exposureResult]);

  const filteredRecords = useMemo(() => {
    const base = exposureResult?.records || [];
    const searchLower = localFilterText.trim().toLowerCase();

    const filtered = base.filter((rec) => {
      if (categoryFilter === "credentials") {
        if (rec.category !== "infostealer_infection" && rec.category !== "credential_breach") {
          return false;
        }
      } else if (categoryFilter === "endpoints" && rec.category !== "compromised_endpoint") {
        return false;
      } else if (categoryFilter === "network" && rec.category !== "network_exposure") {
        return false;
      } else if (categoryFilter === "surface" && rec.category !== "attack_surface_url") {
        return false;
      }

      if (searchLower) {
        const haystack =
          `${rec.title} ${rec.target} ${rec.summary} ${rec.source_name} ${rec.cve_id || ""}`.toLowerCase();
        return haystack.includes(searchLower);
      }
      return true;
    });

    if (sortMode === "newest") {
      return [...filtered].sort((a, b) => {
        const ta = a.occurred_at ? Date.parse(a.occurred_at) : 0;
        const tb = b.occurred_at ? Date.parse(b.occurred_at) : 0;
        if (tb !== ta) return tb - ta;
        return (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0);
      });
    }

    return filtered;
  }, [exposureResult, categoryFilter, localFilterText, sortMode]);

  const totalPages = Math.max(1, Math.ceil(filteredRecords.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const paginatedRecords = useMemo(() => {
    const start = (safePage - 1) * PAGE_SIZE;
    return filteredRecords.slice(start, start + PAGE_SIZE);
  }, [filteredRecords, safePage]);

  const stealerFamiliesEntries = useMemo(
    () => Object.entries(exposureResult?.hudson_rock_overview?.stealer_families || {}),
    [exposureResult],
  );

  const succeededProvidersCount = useMemo(
    () =>
      (exposureResult?.sources_queried || []).filter(
        (s) => s.status === "succeeded" || s.status === "no_records",
      ).length,
    [exposureResult],
  );

  if (loading) {
    return (
      <div className="flex items-center gap-2 py-8 text-xs text-zinc-400">
        <RefreshCw className="h-3.5 w-3.5 animate-spin text-zinc-500" />
        Loading Threat Intelligence workspace...
      </div>
    );
  }

  const hasSubdomains = (exposureResult?.discovered_subdomains.length || 0) > 0;
  const hasThirdParty =
    (exposureResult?.hudson_rock_overview.third_party_domains.length || 0) > 0;
  const visibleSubdomains = showAllSubdomains
    ? exposureResult?.discovered_subdomains || []
    : (exposureResult?.discovered_subdomains || []).slice(0, 10);

  return (
    <div className="space-y-6">
      {/* Studio Page Header */}
      <PageHeader
        eyebrow="Rules & Threat Intelligence"
        title="Threat Intelligence & Compromise OSINT"
        description="Correlate live Hudson Rock infostealer telemetry, breached credentials, passive DNS/ports, and CISA KEV / EPSS vulnerability intelligence."
        actions={
          <button
            type="button"
            onClick={handleBatchEnrich}
            disabled={enriching}
            className="vf-btn-primary h-8 px-4 text-xs"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${enriching ? "animate-spin" : ""}`} />
            {enriching ? "Enriching Findings..." : "Batch Enrich Findings"}
          </button>
        }
      />

      {error && <NoticeBanner tone="error" title="Catalog Load Error" message={error} onRetry={loadData} />}

      {actionMessage && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-white/[0.08] bg-[#131317] px-4 py-3 text-xs text-zinc-200 shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]">
          <div className="flex items-center gap-2.5 min-w-0">
            <span
              className={`h-2 w-2 shrink-0 rounded-full ${
                actionTone === "error"
                  ? "bg-rose-400"
                  : actionTone === "info"
                    ? "bg-[#5b8ef8]"
                    : "bg-emerald-400"
              }`}
            />
            <span className="break-words">{actionMessage}</span>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <Link
              href={`/organizations/${orgId}/findings`}
              className="vf-btn-secondary h-7 px-3 text-xs"
            >
              View in Issues &amp; Fixes →
            </Link>
            <button
              type="button"
              onClick={() => setActionMessage(null)}
              aria-label="Dismiss notification"
              className="vf-btn-ghost h-7 w-7 p-0"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* Top KPI Strip (VForge StatCard Grammar) */}
      {summary && (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard
            label="Tracked Findings"
            value={summary.total_findings}
            sublabel="Across active scans & OSINT imports"
            icon={<ShieldAlert className="h-4 w-4" />}
            href={`/organizations/${orgId}/findings`}
          />
          <StatCard
            label="Actively Exploited (KEV)"
            value={summary.kev_findings_count}
            sublabel="CISA Known Exploited Catalog"
            icon={<Flame className="h-4 w-4" />}
            tone={summary.kev_findings_count > 0 ? "danger" : "default"}
          />
          <StatCard
            label="High EPSS (> 50%)"
            value={summary.high_epss_findings_count}
            sublabel="Elevated 30-day exploit probability"
            icon={<TrendingUp className="h-4 w-4" />}
            tone={summary.high_epss_findings_count > 0 ? "warning" : "default"}
          />
          <StatCard
            label="Registered Intel Feeds"
            value={sources.length}
            sublabel="Vulnerability & OSINT connectors"
            icon={<Database className="h-4 w-4" />}
          />
        </div>
      )}

      {/* Workspace Segmented Tabs */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.06] pb-3">
        <div
          role="tablist"
          aria-label="Threat Intelligence views"
          className="inline-flex flex-wrap items-center gap-1 rounded-full border border-white/[0.068] bg-[#101013] p-1"
        >
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "osint"}
            onClick={() => setActiveTab("osint")}
            className={
              activeTab === "osint"
                ? "vf-btn-primary h-7 px-3.5 text-xs"
                : "vf-btn-ghost h-7 rounded-full px-3.5 text-xs"
            }
          >
            <Radar className="h-3.5 w-3.5" />
            Compromise OSINT
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "cve"}
            onClick={() => setActiveTab("cve")}
            className={
              activeTab === "cve"
                ? "vf-btn-primary h-7 px-3.5 text-xs"
                : "vf-btn-ghost h-7 rounded-full px-3.5 text-xs"
            }
          >
            <Search className="h-3.5 w-3.5" />
            CVE Lookup
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "sources"}
            onClick={() => setActiveTab("sources")}
            className={
              activeTab === "sources"
                ? "vf-btn-primary h-7 px-3.5 text-xs"
                : "vf-btn-ghost h-7 rounded-full px-3.5 text-xs"
            }
          >
            <Database className="h-3.5 w-3.5" />
            Intel Sources
            <span className="ml-0.5 rounded-full bg-white/[0.1] px-1.5 py-0.2 text-[10px] tabular-nums">
              {sources.length}
            </span>
          </button>
        </div>

        <div className="hidden items-center gap-2 text-[11px] text-zinc-500 sm:flex">
          <ShieldCheck className="h-3.5 w-3.5 text-emerald-400/80" />
          <span>Passwords automatically redacted on ingestion</span>
        </div>
      </div>

      {/* TAB 1: MULTI-SOURCE COMPROMISE & EXPOSURE OSINT */}
      {activeTab === "osint" && (
        <Panel className="space-y-5">
          <SectionHeader
            title="Compromised Credentials, Infostealer & Exposure Search"
            description="Correlate Hudson Rock Cavalier OSINT v2, XposedOrNot, ProxyNova COMB, Shodan InternetDB, HackerTarget DNS, crt.sh, AlienVault OTX, URLScan.io, and Wayback CDX."
            action={<Badge tone="info" dot>9 Live OSINT Engines</Badge>}
          />

          {/* Unified Command Bar */}
          <form onSubmit={handleExposureSubmit} className="space-y-3">
            <div className="grid grid-cols-1 gap-2.5 md:grid-cols-12">
              <div className="relative md:col-span-6 lg:col-span-7">
                <label htmlFor="osint-query" className="sr-only">
                  Domain, @Email Domain, Email, IP Address, or Company Name
                </label>
                <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
                <input
                  id="osint-query"
                  type="text"
                  value={exposureQuery}
                  onChange={(e) => setExposureQuery(e.target.value)}
                  placeholder="Domain, @domain.com, email, IP address, or company name..."
                  className="vf-input h-9 pl-9 pr-8 text-xs"
                />
                {exposureQuery && (
                  <button
                    type="button"
                    onClick={() => setExposureQuery("")}
                    aria-label="Clear search query"
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-200"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                )}
              </div>

              <div className="md:col-span-3 lg:col-span-3">
                <Select
                  size="sm"
                  aria-label="Indicator Type"
                  value={exposureQueryType}
                  onChange={(e) => setExposureQueryType(e.target.value as ExposureQueryType)}
                >
                  <option value="auto">Auto-Detect Indicator</option>
                  <option value="domain">Domain / @Domain</option>
                  <option value="email">Email Address</option>
                  <option value="company">Company Name</option>
                  <option value="ip">IPv4 / IPv6 Address</option>
                  <option value="username">Username / Handle</option>
                </Select>
              </div>

              <div className="md:col-span-3 lg:col-span-2">
                <button
                  type="submit"
                  disabled={exposureLoading || !exposureQuery.trim()}
                  className="vf-btn-primary h-9 w-full px-4 text-xs"
                >
                  {exposureLoading ? (
                    <>
                      <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                      Correlating...
                    </>
                  ) : (
                    "Search Intel"
                  )}
                </button>
              </div>
            </div>

            {/* Clean Single-Line Example Indicators */}
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="mr-1 text-[11px] text-zinc-500">Try:</span>
              {EXAMPLE_QUERIES.map((preset) => (
                <button
                  key={preset.query}
                  type="button"
                  disabled={exposureLoading}
                  onClick={() => handleQuickPreset(preset.query, preset.type)}
                  className="inline-flex items-center rounded-full border border-white/[0.07] bg-[#101013] px-2.5 py-0.5 font-mono text-[11px] text-zinc-400 transition hover:border-white/[0.16] hover:bg-[#18181d] hover:text-zinc-100 disabled:opacity-50"
                >
                  {preset.label}
                </button>
              ))}
            </div>
          </form>

          {exposureError && (
            <NoticeBanner tone="error" title="Correlation Error" message={exposureError} />
          )}

          {!exposureResult && !exposureLoading && !exposureError && (
            <EmptyState
              icon={<Radar className="h-6 w-6" />}
              title="Ready to Correlate External Compromise Intelligence"
              description="Submit a domain, @domain shorthand, email address, IP, or company name to query Hudson Rock Cavalier and 8 public OSINT engines concurrently."
              actionLabel="Run Demo Lookup (example.com)"
              onAction={() => handleQuickPreset("example.com", "domain")}
            />
          )}

          {exposureResult && (
            <div className="space-y-5 border-t border-white/[0.06] pt-5">
              {/* Compact 4-Card Exposure Telemetry Summary */}
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
                <div className="flex flex-col justify-between rounded-xl border border-white/[0.068] bg-[#101013] p-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-medium text-zinc-400">Most Recent Compromise</span>
                    <Activity className="h-3.5 w-3.5 text-zinc-500" />
                  </div>
                  <div className="mt-2.5">
                    <div
                      className={`font-mono text-sm font-semibold tabular-nums ${
                        exposureResult.latest_compromise_at ? "text-rose-300" : "text-zinc-300"
                      }`}
                    >
                      {exposureResult.latest_compromise_at
                        ? formatUtc(exposureResult.latest_compromise_at)
                        : "No dated breach"}
                    </div>
                    <p
                      className="mt-1 truncate text-[11px] text-zinc-500"
                      title={`${exposureResult.detected_type}: ${exposureResult.normalized_query}`}
                    >
                      <span className="uppercase text-zinc-400">{exposureResult.detected_type}</span>
                      {" · "}
                      <span className="font-mono text-zinc-300">
                        {exposureResult.normalized_query}
                      </span>
                    </p>
                  </div>
                </div>

                <div className="flex flex-col justify-between rounded-xl border border-white/[0.068] bg-[#101013] p-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-medium text-zinc-400">
                      Hudson Rock Stealer Hits
                    </span>
                    <ShieldAlert className="h-3.5 w-3.5 text-zinc-500" />
                  </div>
                  <div className="mt-2.5">
                    <div className="text-2xl font-semibold tracking-tight text-white tabular-nums">
                      {exposureResult.hudson_rock_overview.total_hits}
                    </div>
                    <p className="mt-1 text-[11px] text-zinc-400 tabular-nums">
                      <span className="text-rose-300">
                        {exposureResult.hudson_rock_overview.employees_compromised} emp
                      </span>
                      {" · "}
                      <span className="text-amber-300">
                        {exposureResult.hudson_rock_overview.users_compromised} users
                      </span>
                      {" · "}
                      <span>{exposureResult.hudson_rock_overview.third_parties_compromised} 3rd-party</span>
                    </p>
                  </div>
                </div>

                <div className="flex flex-col justify-between rounded-xl border border-white/[0.068] bg-[#101013] p-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-medium text-zinc-400">
                      Stealer Families &amp; Hygiene
                    </span>
                    <Flame className="h-3.5 w-3.5 text-zinc-500" />
                  </div>
                  <div className="mt-2.5">
                    <div className="flex flex-wrap gap-1">
                      {stealerFamiliesEntries.length > 0 ? (
                        stealerFamiliesEntries.slice(0, 4).map(([fam, cnt]) => (
                          <Badge key={fam} tone="danger" className="font-mono text-[10px]">
                            {fam}: {cnt}
                          </Badge>
                        ))
                      ) : (
                        <span className="text-xs text-zinc-500">None observed</span>
                      )}
                    </div>
                    {exposureResult.hudson_rock_overview.weak_user_password_pct !== null &&
                      exposureResult.hudson_rock_overview.weak_user_password_pct !== undefined && (
                        <p className="mt-1.5 text-[11px] text-zinc-400 tabular-nums">
                          Weak passwords:{" "}
                          <span className="font-medium text-amber-300">
                            {exposureResult.hudson_rock_overview.weak_user_password_pct.toFixed(1)}%
                          </span>
                        </p>
                      )}
                  </div>
                </div>

                <div className="flex flex-col justify-between rounded-xl border border-white/[0.068] bg-[#101013] p-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-medium text-zinc-400">Correlated Footprint</span>
                    <Globe className="h-3.5 w-3.5 text-zinc-500" />
                  </div>
                  <div className="mt-2.5 space-y-1">
                    <div className="flex flex-wrap items-center gap-1.5 text-xs tabular-nums">
                      <span className="font-semibold text-white">
                        {exposureResult.discovered_subdomains.length}
                      </span>
                      <span className="text-zinc-500">hosts</span>
                      <span className="text-zinc-700">·</span>
                      <span className="font-semibold text-white">
                        {exposureResult.resolved_ips.length}
                      </span>
                      <span className="text-zinc-500">IPs</span>
                      <span className="text-zinc-700">·</span>
                      <span className="font-semibold text-white">
                        {exposureResult.total_records}
                      </span>
                      <span className="text-zinc-500">signals</span>
                    </div>
                    <p
                      className="truncate font-mono text-[11px] text-zinc-400"
                      title={exposureResult.resolved_ips.join(", ") || "No IPs resolved"}
                    >
                      <span className="text-rose-300">{exposureResult.critical_count} crit</span>
                      {" · "}
                      <span className="text-amber-300">{exposureResult.high_count} high</span>
                      {" · "}
                      <span>{exposureResult.medium_count} med</span>
                    </p>
                  </div>
                </div>
              </div>

              {/* Adaptive Subdomains & Co-Compromised Domains Drawer */}
              {(hasSubdomains || hasThirdParty) && (
                <div
                  className={`grid grid-cols-1 gap-3 ${
                    hasSubdomains && hasThirdParty ? "lg:grid-cols-2" : ""
                  }`}
                >
                  {hasSubdomains && (
                    <div className="rounded-xl border border-white/[0.068] bg-[#101013] p-3.5">
                      <div className="mb-2.5 flex items-center justify-between gap-2">
                        <span className="text-[11px] font-medium text-zinc-400">
                          Discovered Subdomains &amp; Portals (
                          {exposureResult.discovered_subdomains.length})
                        </span>
                        {exposureResult.discovered_subdomains.length > 10 && (
                          <button
                            type="button"
                            onClick={() => setShowAllSubdomains((prev) => !prev)}
                            className="text-[11px] font-medium text-[#5b8ef8] hover:text-[#93c5fd]"
                          >
                            {showAllSubdomains
                              ? "Show less"
                              : `Show all ${exposureResult.discovered_subdomains.length}`}
                          </button>
                        )}
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {visibleSubdomains.map((sub) => (
                          <button
                            key={sub}
                            type="button"
                            title={`Pivot search ${sub}`}
                            onClick={() => handleQuickPreset(sub, "domain")}
                            className="max-w-full truncate rounded-md border border-white/[0.075] bg-[#16161b] px-2 py-0.5 font-mono text-[11px] text-zinc-300 transition hover:border-white/[0.18] hover:text-white"
                          >
                            {sub}
                          </button>
                        ))}
                      </div>
                    </div>
                  )}

                  {hasThirdParty && (
                    <div className="rounded-xl border border-white/[0.068] bg-[#101013] p-3.5">
                      <div className="mb-2.5 text-[11px] font-medium text-zinc-400">
                        Co-Compromised Third-Party &amp; Origin Infrastructure (
                        {exposureResult.hudson_rock_overview.third_party_domains.length})
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {exposureResult.hudson_rock_overview.third_party_domains.map((tp) => (
                          <button
                            key={tp.domain}
                            type="button"
                            title={`Pivot search ${tp.domain}`}
                            onClick={() => handleQuickPreset(tp.domain, "auto")}
                            className="inline-flex items-center gap-1 rounded-md border border-white/[0.08] bg-[#19191e] px-2 py-0.5 font-mono text-[11px] text-amber-300/90 transition hover:border-amber-400/35 hover:text-amber-200"
                          >
                            <span className="max-w-[180px] truncate">{tp.domain}</span>
                            <span className="text-[10px] text-zinc-500">({tp.occurrence})</span>
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Dense Filter, Sort & Target Project Bar */}
              <div className="space-y-3">
                <div className="flex flex-wrap items-center gap-1.5">
                  {[
                    { id: "all", label: "All", count: categoryCounts.all },
                    { id: "credentials", label: "Infostealer & Credentials", count: categoryCounts.credentials },
                    { id: "endpoints", label: "Compromised Portals", count: categoryCounts.endpoints },
                    { id: "network", label: "Network & CVEs", count: categoryCounts.network },
                    { id: "surface", label: "Attack Surface", count: categoryCounts.surface },
                  ].map((tab) => (
                    <button
                      key={tab.id}
                      type="button"
                      onClick={() => {
                        setCategoryFilter(tab.id);
                        setPage(1);
                      }}
                      className={
                        categoryFilter === tab.id
                          ? "vf-btn-primary h-7 px-3 text-xs"
                          : "vf-btn-secondary h-7 px-3 text-xs"
                      }
                    >
                      <span>{tab.label}</span>
                      <span
                        className={`rounded-full px-1.5 text-[10px] tabular-nums ${
                          categoryFilter === tab.id
                            ? "bg-white/20 text-white"
                            : "bg-white/[0.06] text-zinc-400"
                        }`}
                      >
                        {tab.count}
                      </span>
                    </button>
                  ))}
                </div>

                <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-12">
                  <div className="relative lg:col-span-5">
                    <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
                    <input
                      type="text"
                      value={localFilterText}
                      onChange={(e) => {
                        setLocalFilterText(e.target.value);
                        setPage(1);
                      }}
                      placeholder="Filter records by URL, source, CVE, or IP..."
                      className="vf-input h-8 pl-8 pr-7 text-xs"
                    />
                    {localFilterText && (
                      <button
                        type="button"
                        onClick={() => {
                          setLocalFilterText("");
                          setPage(1);
                        }}
                        aria-label="Clear record filter"
                        className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-200"
                      >
                        <X className="h-3.5 w-3.5" />
                      </button>
                    )}
                  </div>

                  <div className="lg:col-span-3">
                    <Select
                      size="sm"
                      aria-label="Sort Exposure Records"
                      value={sortMode}
                      onChange={(e) => {
                        setSortMode(e.target.value as ExposureSortMode);
                        setPage(1);
                      }}
                    >
                      <option value="priority">Sort: Priority &amp; Severity</option>
                      <option value="newest">Sort: Most Recent First</option>
                    </Select>
                  </div>

                  {projects.length > 0 && (
                    <div className="lg:col-span-4">
                      <Select
                        size="sm"
                        aria-label="Import Target Project"
                        value={selectedProjectId}
                        onChange={(e) => setSelectedProjectId(e.target.value)}
                      >
                        {projects.map((p) => (
                          <option key={p.id} value={p.id}>
                            Track in: {p.name}
                          </option>
                        ))}
                      </Select>
                    </div>
                  )}
                </div>
              </div>

              {/* Studio Exposure Feed (Compact Expandable Rows + Pagination) */}
              {filteredRecords.length === 0 ? (
                <EmptyState
                  icon={<Search className="h-5 w-5" />}
                  title="No matching exposure signals"
                  description="Try clearing the text filter or switching back to the All category."
                  actionLabel="Reset Filters"
                  onAction={() => {
                    setCategoryFilter("all");
                    setLocalFilterText("");
                    setPage(1);
                  }}
                />
              ) : (
                <div className="overflow-hidden rounded-xl border border-white/[0.068] bg-[#101013]">
                  <div className="divide-y divide-white/[0.06]">
                    {paginatedRecords.map((rec) => {
                      const importedFindingId = importedRecordIds[rec.record_id];
                      const isExpanded = Boolean(expandedRecords[rec.record_id]);
                      const isHighPriority =
                        rec.severity === "critical" || rec.severity === "high";

                      return (
                        <div
                          key={rec.record_id}
                          className="transition hover:bg-white/[0.02]"
                        >
                          <div className="flex flex-col gap-3 p-4 lg:flex-row lg:items-start lg:justify-between">
                            {/* Left Signal Info */}
                            <div className="min-w-0 flex-1 space-y-1.5">
                              <div className="flex flex-wrap items-center gap-1.5">
                                <SeverityBadge severity={rec.severity} />
                                <Badge tone="neutral" className="font-mono text-[10px]">
                                  {rec.source_name}
                                </Badge>
                                <Badge tone="neutral" className="text-[10px] text-zinc-400">
                                  {CATEGORY_LABEL[rec.category] || rec.category}
                                </Badge>
                                {rec.is_known_exploited && (
                                  <Badge tone="danger" dot>
                                    CISA KEV
                                  </Badge>
                                )}
                                {rec.occurred_at && (
                                  <span className="font-mono text-[11px] text-zinc-400 tabular-nums">
                                    {formatUtc(rec.occurred_at)}
                                  </span>
                                )}
                              </div>

                              <button
                                type="button"
                                onClick={() => toggleExpandRecord(rec.record_id)}
                                className="block w-full text-left"
                              >
                                <h3 className="text-[13px] font-semibold leading-snug text-zinc-100 break-words hover:text-white">
                                  {rec.title}
                                </h3>
                              </button>

                              <div className="flex items-center gap-2 min-w-0">
                                <span
                                  className="truncate font-mono text-[11px] text-[#93c5fd]/90"
                                  title={rec.target}
                                >
                                  {rec.target}
                                </span>
                                <button
                                  type="button"
                                  onClick={() => void handleCopyText(rec.record_id, rec.target)}
                                  title="Copy target indicator"
                                  className="shrink-0 text-zinc-500 transition hover:text-zinc-200"
                                >
                                  {copiedId === rec.record_id ? (
                                    <Check className="h-3 w-3 text-emerald-400" />
                                  ) : (
                                    <Copy className="h-3 w-3" />
                                  )}
                                </button>
                              </div>

                              <p
                                className={`text-xs leading-relaxed text-zinc-400 ${
                                  isExpanded || isHighPriority ? "" : "line-clamp-2"
                                }`}
                              >
                                {rec.summary}
                              </p>
                            </div>

                            {/* Right Action Cluster */}
                            <div className="flex flex-wrap items-center gap-2 lg:shrink-0 lg:justify-end">
                              {importedFindingId ? (
                                <Link
                                  href={`/organizations/${orgId}/findings`}
                                  className="vf-btn-secondary h-7 px-3 text-xs text-emerald-300"
                                >
                                  ✓ Tracked in Findings →
                                </Link>
                              ) : (
                                <button
                                  type="button"
                                  onClick={() => void handleImportAsFinding(rec)}
                                  disabled={
                                    importingRecordId === rec.record_id || projects.length === 0
                                  }
                                  className="vf-btn-secondary h-7 px-3 text-xs"
                                >
                                  {importingRecordId === rec.record_id
                                    ? "Importing..."
                                    : "+ Track as Finding"}
                                </button>
                              )}

                              {rec.remediation && (
                                <button
                                  type="button"
                                  onClick={() => toggleExpandRecord(rec.record_id)}
                                  aria-expanded={isExpanded}
                                  className="vf-btn-ghost h-7 px-2.5 text-[11px]"
                                >
                                  {isExpanded ? "Hide Action" : "Remediation"}
                                  {isExpanded ? (
                                    <ChevronUp className="h-3.5 w-3.5" />
                                  ) : (
                                    <ChevronDown className="h-3.5 w-3.5" />
                                  )}
                                </button>
                              )}
                            </div>
                          </div>

                          {/* Expandable Remediation & Full Target Drawer */}
                          {isExpanded && (
                            <div className="border-t border-white/[0.05] bg-[#141418]/60 px-4 py-3 space-y-2">
                              <div className="break-all font-mono text-[11px] text-zinc-300">
                                <span className="text-zinc-500">Full Target: </span>
                                {rec.target}
                              </div>
                              {rec.remediation && (
                                <div className="border-l-2 border-[#2f71e3]/70 pl-3 text-xs leading-relaxed text-zinc-300">
                                  <span className="font-medium text-zinc-100">
                                    Recommended Action:{" "}
                                  </span>
                                  {rec.remediation}
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>

                  {/* Pagination Footer */}
                  {totalPages > 1 && (
                    <div className="flex flex-wrap items-center justify-between gap-2 border-t border-white/[0.06] bg-[#141417] px-4 py-2.5 text-xs text-zinc-400">
                      <span className="tabular-nums">
                        Showing {(safePage - 1) * PAGE_SIZE + 1}–
                        {Math.min(safePage * PAGE_SIZE, filteredRecords.length)} of{" "}
                        {filteredRecords.length} records
                      </span>
                      <div className="flex items-center gap-1.5">
                        <button
                          type="button"
                          disabled={safePage <= 1}
                          onClick={() => setPage((p) => Math.max(1, p - 1))}
                          className="vf-btn-secondary h-7 px-2.5 text-xs"
                        >
                          <ChevronLeft className="h-3.5 w-3.5" />
                          Prev
                        </button>
                        <span className="px-2 text-[11px] tabular-nums text-zinc-300">
                          {safePage} / {totalPages}
                        </span>
                        <button
                          type="button"
                          disabled={safePage >= totalPages}
                          onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                          className="vf-btn-secondary h-7 px-2.5 text-xs"
                        >
                          Next
                          <ChevronRight className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Collapsible Provider Telemetry & SHA-256 Provenance */}
              <div className="overflow-hidden rounded-xl border border-white/[0.068] bg-[#101013]">
                <button
                  type="button"
                  onClick={() => setShowProvenance((prev) => !prev)}
                  className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left transition hover:bg-white/[0.02]"
                >
                  <div className="flex flex-wrap items-center gap-2 min-w-0">
                    <Server className="h-3.5 w-3.5 shrink-0 text-zinc-500" />
                    <span className="text-xs font-medium text-zinc-200">
                      Upstream Provider Telemetry &amp; SHA-256 Provenance
                    </span>
                    <Badge tone="neutral" className="tabular-nums">
                      {succeededProvidersCount}/{exposureResult.sources_queried.length} responded
                    </Badge>
                  </div>
                  <div className="flex items-center gap-2 shrink-0 text-[11px] text-zinc-500">
                    <span className="hidden sm:inline tabular-nums">
                      {formatUtc(exposureResult.searched_at)}
                    </span>
                    {showProvenance ? (
                      <ChevronUp className="h-4 w-4 text-zinc-400" />
                    ) : (
                      <ChevronDown className="h-4 w-4 text-zinc-400" />
                    )}
                  </div>
                </button>

                {showProvenance && (
                  <div className="border-t border-white/[0.06]">
                    <DataTableWrapper>
                      <thead>
                        <tr>
                          <Th>Provider</Th>
                          <Th>Status</Th>
                          <Th>Records</Th>
                          <Th>Latency</Th>
                          <Th className="hidden md:table-cell">HTTP</Th>
                          <Th className="hidden lg:table-cell">Payload SHA-256</Th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-white/[0.05]">
                        {exposureResult.sources_queried.map((st, idx) => (
                          <tr
                            key={`${st.source_slug}-${idx}`}
                            className="hover:bg-white/[0.02]"
                          >
                            <Td>
                              <div className="font-medium text-zinc-100">{st.source_name}</div>
                              <div className="font-mono text-[11px] text-zinc-500">
                                {st.source_slug}
                              </div>
                            </Td>
                            <Td className="whitespace-nowrap">
                              <StatusBadge
                                status={
                                  st.status === "succeeded"
                                    ? "ok"
                                    : st.status === "no_records"
                                      ? "inactive"
                                      : "warning"
                                }
                                label={st.status.replaceAll("_", " ")}
                              />
                            </Td>
                            <Td className="font-mono tabular-nums text-zinc-100">
                              {st.records_found}
                            </Td>
                            <Td className="whitespace-nowrap font-mono tabular-nums text-zinc-400">
                              {st.latency_ms} ms
                            </Td>
                            <Td className="hidden font-mono text-zinc-400 md:table-cell">
                              {st.http_status ?? "—"}
                            </Td>
                            <Td className="hidden font-mono text-[11px] text-zinc-500 lg:table-cell">
                              {st.raw_sha256.slice(0, 16)}…
                            </Td>
                          </tr>
                        ))}
                      </tbody>
                    </DataTableWrapper>
                  </div>
                )}
              </div>
            </div>
          )}
        </Panel>
      )}

      {/* TAB 2: CVE POINT-LOOKUP */}
      {activeTab === "cve" && (
        <Panel className="space-y-5">
          <SectionHeader
            title="CVE Threat Intelligence Point-Lookup"
            description="Query aggregated real-time vulnerability intelligence across CISA KEV, FIRST EPSS, NVD CVSS, Exploit-DB, and OSV."
          />

          <form onSubmit={handleCveLookup} className="flex flex-col gap-2.5 sm:flex-row">
            <div className="relative flex-1 sm:max-w-md">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
              <input
                type="text"
                value={cveSearch}
                onChange={(e) => setCveSearch(e.target.value)}
                placeholder="e.g. CVE-2021-44228"
                className="vf-input h-9 pl-9 font-mono text-xs"
              />
            </div>
            <button
              type="submit"
              disabled={cveLoading || !cveSearch.trim()}
              className="vf-btn-primary h-9 px-4 text-xs"
            >
              {cveLoading ? "Querying..." : "Lookup CVE"}
            </button>
          </form>

          {cveError && <NoticeBanner tone="warning" title="CVE Lookup Notice" message={cveError} />}

          {!cveIntel && !cveLoading && !cveError && (
            <EmptyState
              icon={<Search className="h-5 w-5" />}
              title="Inspect Any CVE Identifier"
              description="Enter a CVE identifier to inspect CISA KEV exploitation status, EPSS probability scores, CVSS v3.1 vectors, and public exploit PoCs."
              actionLabel="Lookup CVE-2021-44228 (Log4Shell)"
              onAction={() => {
                setCveSearch("CVE-2021-44228");
                void handleCveLookup();
              }}
            />
          )}

          {cveIntel && (
            <div className="space-y-4 rounded-xl border border-white/[0.068] bg-[#101013] p-5">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] pb-3.5">
                <div className="flex flex-wrap items-center gap-2.5">
                  <span className="font-mono text-base font-semibold text-white">
                    {cveIntel.cve_id}
                  </span>
                  {cveIntel.is_known_exploited ? (
                    <Badge tone="danger" dot>
                      CISA KEV: Actively Exploited
                    </Badge>
                  ) : (
                    <Badge tone="neutral" dot>
                      Not in CISA KEV
                    </Badge>
                  )}
                </div>
                <span className="text-[11px] text-zinc-400">
                  Sources: {cveIntel.sources_used.join(", ") || "None"}
                </span>
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <div className="rounded-xl border border-white/[0.068] bg-[#141417] p-3.5">
                  <div className="text-[11px] font-medium text-zinc-400">
                    EPSS Exploit Probability
                  </div>
                  <div className="mt-1.5 text-xl font-semibold text-amber-300 tabular-nums">
                    {cveIntel.epss_score !== null && cveIntel.epss_score !== undefined
                      ? `${(cveIntel.epss_score * 100).toFixed(2)}%`
                      : "N/A"}
                  </div>
                  <div className="mt-0.5 text-[11px] text-zinc-500">
                    {cveIntel.epss_percentile !== null && cveIntel.epss_percentile !== undefined
                      ? `${(cveIntel.epss_percentile * 100).toFixed(1)}th percentile`
                      : "No percentile data"}
                  </div>
                </div>

                <div className="rounded-xl border border-white/[0.068] bg-[#141417] p-3.5">
                  <div className="text-[11px] font-medium text-zinc-400">NVD CVSS v3.1</div>
                  <div className="mt-1.5 text-xl font-semibold text-white tabular-nums">
                    {cveIntel.cvss_score !== null && cveIntel.cvss_score !== undefined
                      ? cveIntel.cvss_score
                      : "N/A"}
                  </div>
                  <div
                    className="mt-0.5 truncate font-mono text-[11px] text-zinc-500"
                    title={cveIntel.cvss_vector || ""}
                  >
                    {cveIntel.cvss_vector || "No vector available"}
                  </div>
                </div>

                <div className="rounded-xl border border-white/[0.068] bg-[#141417] p-3.5">
                  <div className="text-[11px] font-medium text-zinc-400">CWE Weaknesses</div>
                  <div className="mt-2 flex flex-wrap gap-1">
                    {cveIntel.cwes.length > 0 ? (
                      cveIntel.cwes.map((cwe) => (
                        <Badge key={cwe} tone="neutral" className="font-mono text-[10px]">
                          {cwe}
                        </Badge>
                      ))
                    ) : (
                      <span className="text-xs text-zinc-500">None mapped</span>
                    )}
                  </div>
                </div>
              </div>

              <div>
                <h3 className="text-xs font-medium text-zinc-400">
                  Public Exploit References ({cveIntel.exploit_references.length})
                </h3>
                {cveIntel.exploit_references.length > 0 ? (
                  <ul className="mt-2 divide-y divide-white/[0.05] rounded-xl border border-white/[0.068] bg-[#141417]">
                    {cveIntel.exploit_references.map((ref, idx) => (
                      <li
                        key={idx}
                        className="flex flex-wrap items-center justify-between gap-2 px-3.5 py-2.5 text-xs"
                      >
                        <span className="font-mono font-medium text-amber-300">
                          {String(ref.id || `Ref-${idx}`)}
                        </span>
                        <span className="min-w-0 flex-1 truncate text-zinc-300">
                          {String(ref.title || ref.description || "Exploit PoC")}
                        </span>
                        <Badge tone="neutral">{String(ref.source || "exploit_db")}</Badge>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="mt-1.5 text-xs text-zinc-500">No public exploit references recorded.</p>
                )}
              </div>

              {cveIntel.advisories.length > 0 && (
                <div>
                  <h3 className="text-xs font-medium text-zinc-400">
                    Advisories ({cveIntel.advisories.length})
                  </h3>
                  <ul className="mt-2 divide-y divide-white/[0.05] rounded-xl border border-white/[0.068] bg-[#141417]">
                    {cveIntel.advisories.map((adv, idx) => (
                      <li
                        key={idx}
                        className="flex flex-wrap items-center justify-between gap-2 px-3.5 py-2.5 text-xs"
                      >
                        <span className="font-mono text-[#93c5fd]">
                          {String(adv.id || `Adv-${idx}`)}
                        </span>
                        <span className="min-w-0 flex-1 truncate text-zinc-300">
                          {String(adv.title || "Advisory")}
                        </span>
                        <Badge tone="neutral">{String(adv.source || "advisory")}</Badge>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </Panel>
      )}

      {/* TAB 3: INTELLIGENCE SOURCES CATALOG (100% Responsive Table + Mobile Cards) */}
      {activeTab === "sources" && (
        <Panel className="space-y-4">
          <SectionHeader
            title="Intelligence Sources Catalog"
            description="Registered upstream vulnerability and OSINT connectors with license provenance and strict privacy-boundary gating."
            action={
              <Badge tone="neutral" className="tabular-nums">
                {sources.length} Registered Feeds
              </Badge>
            }
          />

          {/* Desktop Responsive Table (xl+ where sidebar + 6 columns fit with zero clipping) */}
          <div className="hidden overflow-hidden rounded-xl border border-white/[0.068] bg-[#101013] xl:block">
            <DataTableWrapper>
              <thead>
                <tr>
                  <Th>Source</Th>
                  <Th>Type</Th>
                  <Th>Sync Status</Th>
                  <Th className="hidden xl:table-cell">License</Th>
                  <Th>Privacy</Th>
                  <Th className="text-right">Action</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.05]">
                {sources.map((src) => {
                  const summarySrc = summary?.sources?.find((s) => s.slug === src.slug);
                  const rawStatus = summarySrc?.last_sync_status || "never_run";

                  return (
                    <tr key={src.id} className="transition hover:bg-white/[0.02]">
                      <Td className="max-w-[260px]">
                        <div className="font-medium text-zinc-100">{src.name}</div>
                        <div className="mt-0.5 flex items-center gap-2 font-mono text-[11px] text-zinc-500">
                          <span>{src.slug}</span>
                          {src.license_name && (
                            <span className="truncate text-zinc-600 xl:hidden">
                              · {src.license_name}
                            </span>
                          )}
                        </div>
                      </Td>

                      <Td className="whitespace-nowrap">
                        <Badge tone="neutral" className="uppercase text-[10px]">
                          {formatSourceType(src.source_type)}
                        </Badge>
                      </Td>

                      <Td className="whitespace-nowrap">
                        <div className="flex flex-col items-start gap-1">
                          <StatusBadge
                            status={rawStatus === "succeeded" ? "ok" : rawStatus}
                            label={rawStatus === "never_run" ? "Never run" : undefined}
                          />
                          <div className="flex items-center gap-1.5">
                            {summarySrc?.is_stale && (
                              <Badge
                                tone="warning"
                                className="px-2 py-0 text-[10px]"
                              >
                                Stale
                              </Badge>
                            )}
                            {summarySrc?.records_persisted !== undefined &&
                              summarySrc.records_persisted > 0 && (
                                <span className="text-[11px] text-zinc-400 tabular-nums">
                                  {summarySrc.records_persisted.toLocaleString()} records
                                </span>
                              )}
                          </div>
                        </div>
                      </Td>

                      <Td className="hidden max-w-[240px] xl:table-cell">
                        <div className="truncate font-medium text-zinc-200" title={src.license_name}>
                          {src.license_name}
                        </div>
                        <div
                          className="mt-0.5 truncate text-[11px] text-zinc-500"
                          title={src.terms_reference || ""}
                        >
                          {src.terms_reference || "Standard feed terms"}
                        </div>
                      </Td>

                      <Td className="whitespace-nowrap">
                        <div className="flex flex-col items-start gap-1">
                          <Badge tone={src.is_gated ? "warning" : "neutral"} dot>
                            {src.is_gated ? "Gated Feed" : "Open Sync"}
                          </Badge>
                          <span className="text-[11px] text-zinc-500">
                            {src.allow_binary_upload ? "Uploads (Admin)" : "Hash-Only"}
                          </span>
                        </div>
                      </Td>

                      <Td className="whitespace-nowrap text-right">
                        <button
                          type="button"
                          onClick={() => handleSyncSource(src.slug)}
                          disabled={syncingSlug === src.slug}
                          className="vf-btn-secondary h-7 px-3 text-xs"
                        >
                          <RefreshCw
                            className={`h-3 w-3 ${syncingSlug === src.slug ? "animate-spin" : ""}`}
                          />
                          {syncingSlug === src.slug ? "Syncing..." : "Sync Feed"}
                        </button>
                      </Td>
                    </tr>
                  );
                })}
              </tbody>
            </DataTableWrapper>
          </div>

          {/* Mobile, Tablet & Compact Laptop Card Grid (< xl) */}
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:hidden">
            {sources.map((src) => {
              const summarySrc = summary?.sources?.find((s) => s.slug === src.slug);
              const rawStatus = summarySrc?.last_sync_status || "never_run";

              return (
                <div
                  key={src.id}
                  className="flex flex-col justify-between gap-3 rounded-xl border border-white/[0.068] bg-[#101013] p-4"
                >
                  <div className="space-y-2">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <h3 className="text-xs font-semibold text-zinc-100">{src.name}</h3>
                        <p className="font-mono text-[11px] text-zinc-500">{src.slug}</p>
                      </div>
                      <StatusBadge
                        status={rawStatus === "succeeded" ? "ok" : rawStatus}
                        label={rawStatus === "never_run" ? "Never run" : undefined}
                      />
                    </div>

                    <div className="flex flex-wrap items-center gap-1.5">
                      <Badge tone="neutral" className="uppercase text-[10px]">
                        {formatSourceType(src.source_type)}
                      </Badge>
                      <Badge tone={src.is_gated ? "warning" : "neutral"} dot>
                        {src.is_gated ? "Gated Feed" : "Open Sync"}
                      </Badge>
                      {summarySrc?.is_stale && <Badge tone="warning">Stale</Badge>}
                    </div>

                    <p className="text-[11px] leading-relaxed text-zinc-400">
                      <span className="text-zinc-300">{src.license_name}</span>
                      {" · "}
                      {src.allow_binary_upload ? "Uploads Enabled" : "Hash-Only (Zero Upload)"}
                    </p>
                  </div>

                  <div className="flex items-center justify-between gap-2 border-t border-white/[0.05] pt-3">
                    <span className="text-[11px] text-zinc-500 tabular-nums">
                      {summarySrc?.records_persisted
                        ? `${summarySrc.records_persisted.toLocaleString()} cached records`
                        : "No cached snapshot"}
                    </span>
                    <button
                      type="button"
                      onClick={() => handleSyncSource(src.slug)}
                      disabled={syncingSlug === src.slug}
                      className="vf-btn-secondary h-7 px-3 text-xs"
                    >
                      <RefreshCw
                        className={`h-3 w-3 ${syncingSlug === src.slug ? "animate-spin" : ""}`}
                      />
                      {syncingSlug === src.slug ? "Syncing..." : "Sync Feed"}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>

          <div className="flex items-center justify-between border-t border-white/[0.06] pt-3 text-[11px] text-zinc-500">
            <span>
              All upstream fetches preserve SHA-256 provenance and prohibit arbitrary binary uploads.
            </span>
            <Link
              href={`/organizations/${orgId}/findings`}
              className="hidden items-center gap-1 text-zinc-400 hover:text-zinc-200 sm:inline-flex"
            >
              Issues &amp; Fixes <ExternalLink className="h-3 w-3" />
            </Link>
          </div>
        </Panel>
      )}
    </div>
  );
}

export default function ThreatIntelPage() {
  const params = useParams();
  const orgId = typeof params?.orgId === "string" ? params.orgId : "";

  return (
    <OrgShell orgId={orgId}>
      {() => <ThreatIntelContent orgId={orgId} />}
    </OrgShell>
  );
}
