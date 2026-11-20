"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Bug,
  CheckCircle2,
  Code2,
  Cpu,
  FileArchive,
  FolderKanban,
  Globe,
  KeyRound,
  Lock,
  Package,
  Radar,
  RefreshCw,
  ScrollText,
  Server,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import OrgShell, {
  hasPermission,
  useOrgWorkspaceContext,
} from "@/components/OrgShell";
import { Badge, SeverityBadge, StatusBadge } from "@/components/ui/Badge";
import { Panel, SectionHeader, StatCard } from "@/components/ui/Card";
import { PageHeader } from "@/components/ui/PageHeader";
import { EmptyState, NoticeBanner } from "@/components/ui/States";
import { apiFetch, formatUtc } from "@/lib/api";
import type {
  Asset,
  AuditEvent,
  Authorization,
  FindingItem,
  Organization,
  OrgThreatIntelSummary,
  PaginatedResponse,
  RunnerItem,
  ScanRunSummary,
} from "@/lib/types";

const ACTIVE_SCAN_STATUSES = new Set([
  "pending",
  "queued",
  "dispatching",
  "running",
  "canceling",
]);

const OPEN_FINDING_STATUSES = new Set(["open", "in_progress"]);

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

const SEVERITY_META: Record<
  string,
  {
    barClass: string;
    segmentClass: string;
    slaLabel: string;
    weight: number;
  }
> = {
  critical: {
    barClass: "bg-rose-500",
    segmentClass: "bg-rose-500",
    slaLabel: "24h SLA",
    weight: 10,
  },
  high: {
    barClass: "bg-orange-500",
    segmentClass: "bg-orange-500",
    slaLabel: "7d SLA",
    weight: 5,
  },
  medium: {
    barClass: "bg-amber-400",
    segmentClass: "bg-amber-400",
    slaLabel: "30d SLA",
    weight: 2,
  },
  low: {
    barClass: "bg-[#2f71e3]",
    segmentClass: "bg-[#2f71e3]",
    slaLabel: "90d SLA",
    weight: 1,
  },
  info: {
    barClass: "bg-zinc-500",
    segmentClass: "bg-zinc-500",
    slaLabel: "Advisory",
    weight: 0,
  },
};

const DISCIPLINE_CATALOG = [
  {
    key: "secret",
    aliases: ["secret", "secrets", "credential_breach", "infostealer_infection"],
    label: "Secrets & Credentials",
    shortLabel: "SECRET",
    icon: KeyRound,
  },
  {
    key: "dast",
    aliases: ["dast", "web", "api", "compromised_endpoint", "attack_surface_url"],
    label: "Web, API & Portals",
    shortLabel: "DAST",
    icon: Globe,
  },
  {
    key: "sast",
    aliases: ["sast", "code"],
    label: "Static Code Analysis",
    shortLabel: "SAST",
    icon: Code2,
  },
  {
    key: "sca",
    aliases: ["sca", "sbom", "dependency"],
    label: "Supply Chain & SBOM",
    shortLabel: "SCA",
    icon: Package,
  },
  {
    key: "iac",
    aliases: ["iac", "container"],
    label: "IaC & Container Layers",
    shortLabel: "IAC",
    icon: Server,
  },
  {
    key: "network",
    aliases: ["network", "network_exposure", "exploit"],
    label: "Network & Perimeter",
    shortLabel: "NET",
    icon: Cpu,
  },
] as const;

interface TimelineDayBucket {
  dateKey: string;
  shortDate: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  lowInfo: number;
}

interface DashboardData {
  org: Organization;
  assets: Asset[];
  assetsTotal: number;
  authorizations: Authorization[];
  scans: ScanRunSummary[];
  scansTotal: number;
  findings: FindingItem[];
  findingsTotal: number;
  intelSummary: OrgThreatIntelSummary | null;
  runners: RunnerItem[];
  auditEvents: AuditEvent[];
}

function DashboardContent({
  orgId,
  canReadAssets,
  canReadAuthz,
  canReadScans,
  canReadFindings,
  canReadIntel,
  canReadRunners,
  canReadAudit,
  canManageSettings,
}: {
  orgId: string;
  canReadAssets: boolean;
  canReadAuthz: boolean;
  canReadScans: boolean;
  canReadFindings: boolean;
  canReadIntel: boolean;
  canReadRunners: boolean;
  canReadAudit: boolean;
  canManageSettings: boolean;
}) {
  const workspaceCtx = useOrgWorkspaceContext();
  const projects = useMemo(
    () => workspaceCtx?.projects ?? [],
    [workspaceCtx?.projects],
  );
  const selectedProjectId = workspaceCtx?.selectedProjectId ?? "all";

  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedStep, setSelectedStep] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadDashboard = useCallback(
    async (isManualRefresh = false) => {
      if (isManualRefresh) {
        setRefreshing(true);
      }
      try {
        const [
          org,
          assetsRes,
          authzRes,
          scansRes,
          findingsRes,
          intelSummary,
          runnersRes,
          auditRes,
        ] = await Promise.all([
          apiFetch<Organization>(`/api/v1/organizations/${orgId}`),
          canReadAssets
            ? apiFetch<PaginatedResponse<Asset>>(
                `/api/v1/organizations/${orgId}/assets?limit=200`,
              )
            : Promise.resolve({ items: [] as Asset[], total: 0 }),
          canReadAuthz
            ? apiFetch<PaginatedResponse<Authorization>>(
                `/api/v1/organizations/${orgId}/authorizations?limit=200`,
              )
            : Promise.resolve({ items: [] as Authorization[], total: 0 }),
          canReadScans
            ? apiFetch<PaginatedResponse<ScanRunSummary>>(
                `/api/v1/organizations/${orgId}/scans?limit=50`,
              )
            : Promise.resolve({ items: [] as ScanRunSummary[], total: 0 }),
          canReadFindings
            ? apiFetch<PaginatedResponse<FindingItem>>(
                `/api/v1/organizations/${orgId}/findings?limit=200`,
              )
            : Promise.resolve({ items: [] as FindingItem[], total: 0 }),
          canReadIntel
            ? apiFetch<OrgThreatIntelSummary>(
                `/api/v1/organizations/${orgId}/intel/summary`,
              ).catch(() => null)
            : Promise.resolve(null),
          canReadRunners
            ? apiFetch<RunnerItem[]>(
                `/api/v1/organizations/${orgId}/runners`,
              ).catch(() => [] as RunnerItem[])
            : Promise.resolve([] as RunnerItem[]),
          canReadAudit
            ? apiFetch<PaginatedResponse<AuditEvent>>(
                `/api/v1/organizations/${orgId}/audit-events?limit=8`,
              ).catch(() => ({ items: [] as AuditEvent[], total: 0 }))
            : Promise.resolve({ items: [] as AuditEvent[], total: 0 }),
        ]);

        setData({
          org,
          assets: assetsRes.items,
          assetsTotal: assetsRes.total,
          authorizations: authzRes.items,
          scans: scansRes.items,
          scansTotal: scansRes.total,
          findings: findingsRes.items,
          findingsTotal: findingsRes.total,
          intelSummary,
          runners: runnersRes,
          auditEvents: auditRes.items,
        });
        setError(null);
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : "Failed to load organization security posture",
        );
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [
      orgId,
      canReadAssets,
      canReadAuthz,
      canReadScans,
      canReadFindings,
      canReadIntel,
      canReadRunners,
      canReadAudit,
    ],
  );

  useEffect(() => {
    let active = true;
    void Promise.resolve().then(() => {
      if (active) return loadDashboard(false);
    });
    return () => {
      active = false;
    };
  }, [loadDashboard]);

  const projectNames = useMemo(() => {
    const map = new Map<string, string>();
    for (const p of projects) {
      map.set(p.id, p.name);
    }
    return map;
  }, [projects]);

  const scopedAuthorizations = useMemo(() => {
    if (!data) return [];
    if (selectedProjectId === "all") return data.authorizations;
    return data.authorizations.filter((a) => a.project_id === selectedProjectId);
  }, [data, selectedProjectId]);

  const approvedAssetCount = useMemo(() => {
    const approvedIds = new Set(
      scopedAuthorizations
        .filter((a) => a.status === "approved")
        .map((a) => a.asset_id),
    );
    return approvedIds.size;
  }, [scopedAuthorizations]);

  const scopedScans = useMemo(() => {
    if (!data) return [];
    if (selectedProjectId === "all") return data.scans;
    return data.scans.filter((s) => s.project_id === selectedProjectId);
  }, [data, selectedProjectId]);

  const scopedFindings = useMemo(() => {
    if (!data) return [];
    if (selectedProjectId === "all") return data.findings;
    return data.findings.filter((f) => f.project_id === selectedProjectId);
  }, [data, selectedProjectId]);

  const metrics = useMemo(() => {
    const activeScans = scopedScans.filter((s) =>
      ACTIVE_SCAN_STATUSES.has(s.status),
    ).length;

    const openFindings = scopedFindings.filter((f) =>
      OPEN_FINDING_STATUSES.has(f.status),
    );
    const critHighOpen = openFindings.filter(
      (f) => f.severity === "critical" || f.severity === "high",
    );
    const criticalCount = openFindings.filter(
      (f) => f.severity === "critical",
    ).length;
    const highCount = openFindings.filter((f) => f.severity === "high").length;
    const breachedSlaCount = openFindings.filter((f) => f.sla_breached).length;

    const severityCounts: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    for (const f of openFindings) {
      if (f.severity in severityCounts) {
        severityCounts[f.severity] += 1;
      } else {
        severityCounts.info += 1;
      }
    }

    const statusCounts: Record<string, number> = {
      open: 0,
      in_progress: 0,
      resolved: 0,
      risk_accepted: 0,
      false_positive: 0,
    };
    for (const f of scopedFindings) {
      if (f.status in statusCounts) {
        statusCounts[f.status] += 1;
      }
    }

    const disciplineRows = DISCIPLINE_CATALOG.map((disc) => {
      const matched = openFindings.filter((f) => {
        const cat = (f.category || "").toLowerCase();
        return (disc.aliases as readonly string[]).includes(cat);
      });
      const critHigh = matched.filter(
        (f) => f.severity === "critical" || f.severity === "high",
      ).length;
      return {
        ...disc,
        count: matched.length,
        critHigh,
      };
    });
    const activeDisciplineCount = disciplineRows.filter((d) => d.count > 0).length;

    // Build a continuous 14-day observation window ending on the latest observed entity date
    let anchorMs = 0;
    const candidateDates: (string | null | undefined)[] = [
      data?.org.created_at,
      ...scopedFindings.map((f) => f.first_seen_at),
      ...scopedFindings.map((f) => f.last_seen_at),
      ...scopedScans.map((s) => s.created_at),
      ...(data?.auditEvents.map((e) => e.created_at) ?? []),
    ];
    for (const rawDate of candidateDates) {
      if (rawDate) {
        const parsed = Date.parse(rawDate);
        if (!Number.isNaN(parsed) && parsed > anchorMs) {
          anchorMs = parsed;
        }
      }
    }
    if (anchorMs === 0) {
      anchorMs = Date.UTC(2026, 10, 19);
    }
    const anchorDate = new Date(anchorMs);
    const anchorUtcMidnight = Date.UTC(
      anchorDate.getUTCFullYear(),
      anchorDate.getUTCMonth(),
      anchorDate.getUTCDate(),
    );

    const bucketMap = new Map<string, TimelineDayBucket>();
    const timelineDays: TimelineDayBucket[] = [];
    for (let offset = 13; offset >= 0; offset -= 1) {
      const dayDate = new Date(anchorUtcMidnight - offset * 86_400_000);
      const iso = dayDate.toISOString().slice(0, 10);
      const bucket: TimelineDayBucket = {
        dateKey: iso,
        shortDate: iso.slice(5),
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        lowInfo: 0,
      };
      bucketMap.set(iso, bucket);
      timelineDays.push(bucket);
    }

    for (const f of scopedFindings) {
      const dateKey = f.first_seen_at ? f.first_seen_at.slice(0, 10) : null;
      if (!dateKey) continue;
      let bucket = bucketMap.get(dateKey);
      if (!bucket) {
        // Fallback if finding falls outside the 14-day window: map to earliest day bucket
        bucket = timelineDays[0];
      }
      if (bucket) {
        bucket.total += 1;
        if (f.severity === "critical") bucket.critical += 1;
        else if (f.severity === "high") bucket.high += 1;
        else if (f.severity === "medium") bucket.medium += 1;
        else bucket.lowInfo += 1;
      }
    }

    const weightedRiskScore = SEVERITY_ORDER.reduce(
      (acc, sev) => acc + (severityCounts[sev] ?? 0) * (SEVERITY_META[sev]?.weight ?? 0),
      0,
    );

    return {
      activeScans,
      openCount: openFindings.length,
      critHighCount: critHighOpen.length,
      criticalCount,
      highCount,
      breachedSlaCount,
      severityCounts,
      statusCounts,
      disciplineRows,
      activeDisciplineCount,
      timelineDays,
      weightedRiskScore,
    };
  }, [data, scopedScans, scopedFindings]);

  if (loading && !data) {
    return (
      <div className="space-y-4">
        <div className="h-20 animate-pulse rounded-xl border border-white/[0.068] bg-[#141417]/80" />
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {[1, 2, 3, 4].map((idx) => (
            <div
              key={idx}
              className="h-28 animate-pulse rounded-xl border border-white/[0.068] bg-[#141417]/80"
            />
          ))}
        </div>
        <div className="grid gap-4 lg:grid-cols-2">
          <div className="h-64 animate-pulse rounded-xl border border-white/[0.068] bg-[#141417]/80" />
          <div className="h-64 animate-pulse rounded-xl border border-white/[0.068] bg-[#141417]/80" />
        </div>
      </div>
    );
  }

  if (error && !data) {
    return (
      <NoticeBanner
        tone="error"
        title="Unable to load security overview"
        message={error}
        onRetry={() => void loadDashboard(true)}
      />
    );
  }

  if (!data) return null;

  const selectedProjectName =
    selectedProjectId === "all"
      ? "All Projects"
      : projectNames.get(selectedProjectId) ?? "Selected Project";

  const activeRunners = data.runners.filter((r) => r.status === "active").length;
  const maxDisciplineCount = Math.max(
    1,
    ...metrics.disciplineRows.map((d) => d.count),
  );
  const maxTimelineCount = Math.max(
    2,
    ...metrics.timelineDays.map((d) => d.total),
  );
  const windowObservedTotal = metrics.timelineDays.reduce(
    (acc, d) => acc + d.total,
    0,
  );
  const peakTimelineDay = metrics.timelineDays.reduce(
    (best, d) => (d.total > best.total ? d : best),
    metrics.timelineDays[0],
  );
  const totalLifecycleCount = Math.max(1, scopedFindings.length);
  const closedLifecycleCount =
    (metrics.statusCounts.resolved ?? 0) +
    (metrics.statusCounts.risk_accepted ?? 0) +
    (metrics.statusCounts.false_positive ?? 0);
  const resolutionRatePct =
    scopedFindings.length > 0
      ? Math.round((closedLifecycleCount / totalLifecycleCount) * 100)
      : 100;

  const findingSampleTruncated =
    selectedProjectId === "all" && data.findingsTotal > data.findings.length;

  const setupSteps = [
    {
      step: 1,
      title: "Create a Project",
      summary: "Think of a Project as an environment or workload folder (e.g., staging-app).",
      done: projects.length > 0,
      countLabel: `${projects.length} project${projects.length === 1 ? "" : "s"}`,
      href: `/organizations/${orgId}/projects`,
      actionLabel: projects.length > 0 ? "Manage Projects" : "Create Project",
    },
    {
      step: 2,
      title: "Add a Target Asset",
      summary: "Register the URL, domain, IP, Git repo, or container image you want checked.",
      done: data.assetsTotal > 0,
      countLabel: `${data.assetsTotal} target${data.assetsTotal === 1 ? "" : "s"}`,
      href: `/organizations/${orgId}/assets`,
      actionLabel: data.assetsTotal > 0 ? "View Targets" : "Add Target",
    },
    {
      step: 3,
      title: "Approve Scanning",
      summary: "Safety lock: confirm in writing you own or have permission to test this target.",
      done: approvedAssetCount > 0,
      countLabel: `${approvedAssetCount} approved`,
      href: `/organizations/${orgId}/authorizations`,
      actionLabel: approvedAssetCount > 0 ? "View Approvals" : "Approve Target",
    },
    {
      step: 4,
      title: "Launch a Scan",
      summary: "Pick your target and run automated security checks in isolated containers.",
      done: scopedScans.length > 0,
      countLabel: `${scopedScans.length} run${scopedScans.length === 1 ? "" : "s"}`,
      href: `/organizations/${orgId}/scans`,
      actionLabel: scopedScans.length > 0 ? "Scan Center" : "Start First Scan",
    },
    {
      step: 5,
      title: "Review Issues & Fixes",
      summary: "Inspect prioritized findings with remediation steps, risk notes, and reports.",
      done: data.findingsTotal > 0,
      countLabel: `${data.findingsTotal} issue${data.findingsTotal === 1 ? "" : "s"}`,
      href: `/organizations/${orgId}/findings`,
      actionLabel: "View Issues",
    },
  ];
  const completedStepsCount = setupSteps.filter((s) => s.done).length;
  const nextStep = setupSteps.find((s) => !s.done) ?? setupSteps[3];
  const activeStep =
    setupSteps.find((s) => s.step === selectedStep) ?? nextStep;

  return (
    <div className="flex flex-col items-start gap-7 xl:flex-row">
      {/* Main Center Workspace Column */}
      <div className="w-full min-w-0 flex-1 space-y-6">
        <PageHeader
          eyebrow="Workspace Overview"
          title={data.org.name}
          description={`Live security status for ${selectedProjectName}. Follow the guided action dock below or choose any workflow step from the left rail.`}
          actions={
            <div className="flex items-center gap-2">
              <StatusBadge status={data.org.status} />
              <button
                type="button"
                onClick={() => void loadDashboard(true)}
                disabled={refreshing}
                className="vf-btn-ghost h-8 px-2.5 text-xs"
              >
                <RefreshCw
                  className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`}
                />
                {refreshing ? "Refreshing..." : "Refresh"}
              </button>
              {canManageSettings && (
                <Link
                  href={`/organizations/${orgId}/settings`}
                  className="vf-btn-secondary h-8 px-3 text-xs"
                >
                  Settings
                </Link>
              )}
            </div>
          }
        />

        {/* Signature VForge Floating Action & Guide Dock */}
        <section className="vf-dock rounded-2xl p-4 sm:p-5">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] pb-3">
            <div className="flex flex-wrap items-center gap-1">
              {setupSteps.map((item) => {
                const isSelected = activeStep?.step === item.step;
                return (
                  <button
                    key={item.step}
                    type="button"
                    onClick={() => setSelectedStep(item.step)}
                    className={`inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-xs font-medium whitespace-nowrap transition ${
                      isSelected
                        ? "bg-white/[0.09] text-white"
                        : "text-zinc-400 hover:bg-white/[0.04] hover:text-zinc-200"
                    }`}
                  >
                    {item.done ? (
                      <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                    ) : (
                      <span
                        className={`flex h-4 w-4 items-center justify-center rounded-full text-[10px] tabular-nums ${
                          isSelected
                            ? "bg-blue-500/25 text-blue-300"
                            : "bg-white/[0.06] text-zinc-400"
                        }`}
                      >
                        {item.step}
                      </span>
                    )}
                    <span>{item.title.replace(/^Create a |^Add a |^Approve |^Launch a |^Review /, "")}</span>
                  </button>
                );
              })}
            </div>
            <span className="text-[11px] font-medium text-zinc-500 tabular-nums">
              {completedStepsCount}/5 complete
            </span>
          </div>

          {activeStep ? (
            <div className="pt-3.5">
              <div className="text-sm font-medium text-zinc-100">
                Step {activeStep.step}: {activeStep.title}
              </div>
              <p className="mt-1 text-[13px] leading-relaxed text-zinc-400">
                {activeStep.summary}
              </p>
              <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-white/[0.05] pt-3">
                <div className="flex flex-wrap items-center gap-3 text-xs text-zinc-500">
                  <span>{projects.length} projects</span>
                  <span className="text-zinc-700">·</span>
                  <span>{data.assetsTotal} targets</span>
                  <span className="text-zinc-700">·</span>
                  <span>{approvedAssetCount} approved</span>
                  <span className="text-zinc-700">·</span>
                  <span>{scopedScans.length} scan runs</span>
                </div>
                <Link
                  href={activeStep.href}
                  className="vf-btn-primary h-8 rounded-full px-4 text-xs"
                >
                  {activeStep.actionLabel}
                  <ArrowRight className="h-3.5 w-3.5" />
                </Link>
              </div>
            </div>
          ) : null}
        </section>

      {error && (
        <NoticeBanner
          tone="warning"
          message={`Partial refresh warning: ${error}`}
          onRetry={() => void loadDashboard(true)}
        />
      )}

      {selectedProjectId !== "all" && (
        <NoticeBanner
          tone="info"
          message={`Dashboard metrics for scans, findings, and authorizations are filtered to project "${selectedProjectName}". Reset the top-bar project selector to "All projects" for full organization posture.`}
        />
      )}

      {/* Primary KPI Strip */}
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Authorized Targets"
          value={approvedAssetCount}
          sublabel={
            selectedProjectId === "all"
              ? `${data.assetsTotal} registered assets across ${projects.length} projects`
              : `${scopedAuthorizations.length} project authorization records`
          }
          tone={approvedAssetCount > 0 ? "success" : "default"}
          icon={
            <ShieldCheck
              className={`h-4 w-4 ${approvedAssetCount > 0 ? "text-emerald-400" : "text-zinc-500"}`}
            />
          }
          href={
            canReadAuthz ? `/organizations/${orgId}/authorizations` : undefined
          }
        />
        <StatCard
          label="Active Scan Jobs"
          value={metrics.activeScans}
          sublabel={`${scopedScans.length} recent scan runs (${activeRunners} active runners)`}
          tone={metrics.activeScans > 0 ? "info" : "default"}
          icon={
            <Radar
              className={`h-4 w-4 ${metrics.activeScans > 0 ? "text-blue-400" : "text-zinc-500"}`}
            />
          }
          href={canReadScans ? `/organizations/${orgId}/scans` : undefined}
        />
        <StatCard
          label="Open Vulnerabilities"
          value={
            findingSampleTruncated
              ? `${metrics.openCount}+`
              : metrics.openCount
          }
          sublabel={
            metrics.breachedSlaCount > 0
              ? `${metrics.breachedSlaCount} open findings past SLA`
              : `${data.findingsTotal} total findings tracked`
          }
          tone={
            metrics.breachedSlaCount > 0
              ? "danger"
              : metrics.openCount > 0
                ? "warning"
                : "default"
          }
          icon={
            <AlertTriangle
              className={`h-4 w-4 ${
                metrics.breachedSlaCount > 0
                  ? "text-rose-400"
                  : metrics.openCount > 0
                    ? "text-amber-400"
                    : "text-zinc-500"
              }`}
            />
          }
          href={
            canReadFindings ? `/organizations/${orgId}/findings` : undefined
          }
        />
        <StatCard
          label="Critical & High Open"
          value={metrics.critHighCount}
          sublabel={`${metrics.criticalCount} critical, ${metrics.highCount} high${
            data.intelSummary
              ? ` · ${data.intelSummary.kev_findings_count} KEV`
              : ""
          }`}
          tone={metrics.critHighCount > 0 ? "danger" : "default"}
          icon={
            <ShieldAlert
              className={`h-4 w-4 ${metrics.critHighCount > 0 ? "text-rose-400" : "text-zinc-500"}`}
            />
          }
          href={
            canReadFindings
              ? `/organizations/${orgId}/findings?severity=critical`
              : undefined
          }
        />
      </div>

      {/* Distribution & Exposure Row */}
      <div className="grid gap-5 lg:grid-cols-12">
        {/* Severity Distribution */}
        <Panel className="flex flex-col justify-between lg:col-span-6">
          <div>
            <SectionHeader
              title="Vulnerability Severity Distribution"
              description={
                canReadFindings
                  ? "Active open and in-progress findings weighted by severity and SLA window."
                  : "Finding telemetry requires finding:read permission."
              }
              action={
                canReadFindings && (
                  <Link
                    href={`/organizations/${orgId}/findings`}
                    className="inline-flex items-center gap-1 whitespace-nowrap text-xs font-medium text-[#5b8ef8] hover:text-[#93c5fd]"
                  >
                    View Findings <ArrowRight className="h-3 w-3" />
                  </Link>
                )
              }
            />
            {!canReadFindings ? (
              <NoticeBanner
                tone="info"
                message="Your organization role does not include finding:read."
              />
            ) : (
              <div className="space-y-3">
                {/* Top Weighted Risk Index & Proportional Stacked Spectrum */}
                <div className="rounded-xl border border-white/[0.068] bg-[#101013] p-3.5">
                  <div className="flex items-center justify-between gap-2">
                    <div className="min-w-0">
                      <div className="text-[11px] font-medium text-zinc-400">
                        Weighted Exposure Index
                      </div>
                      <div className="mt-1 flex flex-wrap items-center gap-2">
                        <div className="flex items-baseline gap-1">
                          <span className="font-mono text-lg font-semibold text-white tabular-nums">
                            {metrics.weightedRiskScore}
                          </span>
                          <span className="text-[11px] text-zinc-500">pts</span>
                        </div>
                        <Badge
                          tone={
                            metrics.criticalCount > 0
                              ? "danger"
                              : metrics.highCount > 0
                                ? "warning"
                                : metrics.openCount > 0
                                  ? "info"
                                  : "success"
                          }
                          dot
                        >
                          {metrics.criticalCount > 0
                            ? "Critical"
                            : metrics.highCount > 0
                              ? "Elevated"
                              : metrics.openCount > 0
                                ? "Moderate"
                                : "Clean"}
                        </Badge>
                      </div>
                    </div>

                    <div className="shrink-0 text-right">
                      <div className="text-[11px] font-medium text-zinc-400">
                        Active / SLA
                      </div>
                      <div className="mt-1 font-mono text-xs whitespace-nowrap tabular-nums">
                        <span className="font-semibold text-zinc-100">
                          {metrics.openCount} open
                        </span>
                        <span className="mx-1 text-zinc-700">·</span>
                        <span
                          className={
                            metrics.breachedSlaCount > 0
                              ? "text-rose-300"
                              : "text-emerald-400/90"
                          }
                        >
                          {metrics.breachedSlaCount} breached
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Proportional Stacked Spectrum Bar */}
                  <div className="mt-3 flex h-2 w-full gap-0.5 overflow-hidden rounded-full bg-white/[0.05] p-0.5">
                    {metrics.openCount === 0 ? (
                      <div className="h-full w-full rounded-full bg-emerald-500/40" />
                    ) : (
                      SEVERITY_ORDER.map((sev) => {
                        const cnt = metrics.severityCounts[sev] ?? 0;
                        if (cnt <= 0) return null;
                        const pct = Math.max(
                          6,
                          Math.round((cnt / Math.max(1, metrics.openCount)) * 100),
                        );
                        return (
                          <div
                            key={sev}
                            style={{ width: `${pct}%` }}
                            title={`${sev.toUpperCase()}: ${cnt}`}
                            className={`h-full first:rounded-l-full last:rounded-r-full ${
                              SEVERITY_META[sev]?.segmentClass ?? "bg-zinc-500"
                            }`}
                          />
                        );
                      })
                    )}
                  </div>
                </div>

                {/* Interactive Severity Matrix Rows */}
                <div className="space-y-1.5">
                  {SEVERITY_ORDER.map((sev) => {
                    const count = metrics.severityCounts[sev] ?? 0;
                    const sharePct =
                      metrics.openCount > 0
                        ? Math.round((count / metrics.openCount) * 100)
                        : 0;
                    const meta = SEVERITY_META[sev];
                    return (
                      <Link
                        key={sev}
                        href={`/organizations/${orgId}/findings?severity=${sev}`}
                        className="group flex items-center justify-between gap-3 rounded-xl border border-white/[0.055] bg-[#101013] px-3.5 py-2 transition hover:border-white/[0.14] hover:bg-[#16161b]"
                      >
                        <div className="flex w-24 shrink-0 items-center">
                          <SeverityBadge severity={sev} />
                        </div>

                        <span className="hidden w-16 shrink-0 font-mono text-[11px] text-zinc-500 sm:inline-block">
                          {meta?.slaLabel}
                        </span>

                        <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/[0.05]">
                          <div
                            style={{
                              width: count > 0 ? `${Math.max(8, sharePct)}%` : "0%",
                            }}
                            className={`h-full rounded-full transition-all ${
                              meta?.barClass ?? "bg-zinc-500"
                            }`}
                          />
                        </div>

                        <div className="flex w-20 shrink-0 items-center justify-end gap-2 font-mono tabular-nums">
                          <span className="text-[11px] text-zinc-500">
                            {sharePct}%
                          </span>
                          <span
                            className={`w-6 text-right text-xs font-semibold ${
                              count > 0 ? "text-zinc-100" : "text-zinc-500"
                            }`}
                          >
                            {count}
                          </span>
                        </div>
                      </Link>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        </Panel>

        {/* Triage Posture & Threat Intelligence */}
        <Panel className="flex flex-col justify-between lg:col-span-6">
          <div>
            <SectionHeader
              title="Remediation State & Threat Context"
              description="Lifecycle progression, CISA KEV exploitation, and execution runner readiness."
              action={
                canReadIntel && (
                  <Link
                    href={`/organizations/${orgId}/threat-intel`}
                    className="inline-flex items-center gap-1 whitespace-nowrap text-xs font-medium text-[#5b8ef8] hover:text-[#93c5fd]"
                  >
                    Threat Intel <ArrowRight className="h-3 w-3" />
                  </Link>
                )
              }
            />

            <div className="space-y-3">
              {/* Lifecycle Closure Rate Bar */}
              <div className="rounded-xl border border-white/[0.068] bg-[#101013] p-3.5">
                <div className="flex items-center justify-between gap-2 text-xs">
                  <span className="font-medium text-zinc-300">
                    Remediation &amp; Disposition Progress
                  </span>
                  <span className="font-mono text-zinc-200 tabular-nums">
                    <strong className="text-white">{resolutionRatePct}%</strong> closed (
                    {closedLifecycleCount}/{scopedFindings.length})
                  </span>
                </div>
                <div className="mt-2.5 flex h-2 w-full gap-0.5 overflow-hidden rounded-full bg-white/[0.05] p-0.5">
                  {scopedFindings.length === 0 ? (
                    <div className="h-full w-full rounded-full bg-emerald-500/40" />
                  ) : (
                    <>
                      {closedLifecycleCount > 0 && (
                        <div
                          style={{
                            width: `${Math.max(
                              6,
                              Math.round(
                                (closedLifecycleCount / totalLifecycleCount) * 100,
                              ),
                            )}%`,
                          }}
                          className="h-full rounded-l-full bg-emerald-400"
                        />
                      )}
                      {(metrics.statusCounts.in_progress ?? 0) > 0 && (
                        <div
                          style={{
                            width: `${Math.max(
                              6,
                              Math.round(
                                ((metrics.statusCounts.in_progress ?? 0) /
                                  totalLifecycleCount) *
                                  100,
                              ),
                            )}%`,
                          }}
                          className="h-full bg-[#2f71e3]"
                        />
                      )}
                      {(metrics.statusCounts.open ?? 0) > 0 && (
                        <div
                          style={{
                            width: `${Math.max(
                              6,
                              Math.round(
                                ((metrics.statusCounts.open ?? 0) /
                                  totalLifecycleCount) *
                                  100,
                              ),
                            )}%`,
                          }}
                          className="h-full rounded-r-full bg-amber-400"
                        />
                      )}
                    </>
                  )}
                </div>
              </div>

              {/* 3 Primary Lifecycle Cards (Non-Wrapping Labels & Aligned Baselines) */}
              <div className="grid grid-cols-3 gap-2.5">
                {[
                  {
                    key: "open",
                    label: "Open",
                    dot: "bg-amber-400",
                    sub: "Awaiting triage",
                  },
                  {
                    key: "in_progress",
                    label: "In Progress",
                    dot: "bg-[#5b8ef8]",
                    sub: "Active fix",
                  },
                  {
                    key: "resolved",
                    label: "Resolved",
                    dot: "bg-emerald-400",
                    sub: "Verified closed",
                  },
                ].map((item) => (
                  <Link
                    key={item.key}
                    href={`/organizations/${orgId}/findings?status=${item.key}`}
                    className="rounded-xl border border-white/[0.068] bg-[#101013] p-3 transition hover:border-white/[0.14] hover:bg-[#16161b]"
                  >
                    <div className="flex items-center gap-1.5 text-[11px] font-medium whitespace-nowrap text-zinc-400">
                      <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${item.dot}`} />
                      <span className="truncate">{item.label}</span>
                    </div>
                    <div className="mt-1.5 font-mono text-xl font-semibold text-white tabular-nums">
                      {metrics.statusCounts[item.key] ?? 0}
                    </div>
                    <div className="mt-0.5 truncate text-[10px] text-zinc-500">
                      {item.sub}
                    </div>
                  </Link>
                ))}
              </div>

              {/* 2 Secondary Disposition Pills (Wide Horizontal Layout — Zero Wrapping) */}
              <div className="grid grid-cols-2 gap-2.5">
                {[
                  {
                    key: "risk_accepted",
                    label: "Risk Accepted",
                    sub: "Governance exception",
                  },
                  {
                    key: "false_positive",
                    label: "False Positive",
                    sub: "Dismissed noise",
                  },
                ].map((item) => (
                  <Link
                    key={item.key}
                    href={`/organizations/${orgId}/findings?status=${item.key}`}
                    className="flex items-center justify-between gap-2 rounded-xl border border-white/[0.055] bg-[#101013] px-3.5 py-2.5 transition hover:border-white/[0.14] hover:bg-[#16161b]"
                  >
                    <div className="min-w-0">
                      <div className="truncate text-xs font-medium text-zinc-300">
                        {item.label}
                      </div>
                      <div className="truncate text-[10px] text-zinc-500">
                        {item.sub}
                      </div>
                    </div>
                    <span className="font-mono text-base font-semibold text-zinc-100 tabular-nums">
                      {metrics.statusCounts[item.key] ?? 0}
                    </span>
                  </Link>
                ))}
              </div>
            </div>
          </div>

          <div className="mt-3 grid grid-cols-3 gap-2.5 border-t border-white/[0.06] pt-3">
            <Link
              href={`/organizations/${orgId}/threat-intel`}
              className="rounded-xl border border-white/[0.068] bg-[#101013] p-3 transition hover:border-white/[0.14] hover:bg-[#16161b]"
            >
              <div className="truncate text-[11px] text-zinc-400">
                CISA KEV
              </div>
              <div className="mt-1 flex items-center gap-2">
                <span className="font-mono text-base font-semibold text-white tabular-nums">
                  {data.intelSummary ? data.intelSummary.kev_findings_count : "0"}
                </span>
                {data.intelSummary && data.intelSummary.kev_findings_count > 0 && (
                  <Badge tone="danger">KEV</Badge>
                )}
              </div>
            </Link>

            <Link
              href={`/organizations/${orgId}/threat-intel`}
              className="rounded-xl border border-white/[0.068] bg-[#101013] p-3 transition hover:border-white/[0.14] hover:bg-[#16161b]"
            >
              <div className="truncate text-[11px] text-zinc-400">
                High EPSS
              </div>
              <div className="mt-1 font-mono text-base font-semibold text-white tabular-nums">
                {data.intelSummary
                  ? data.intelSummary.high_epss_findings_count
                  : "0"}
              </div>
            </Link>

            <Link
              href={`/organizations/${orgId}/runners`}
              className="rounded-xl border border-white/[0.068] bg-[#101013] p-3 transition hover:border-white/[0.14] hover:bg-[#16161b]"
            >
              <div className="truncate text-[11px] text-zinc-400">
                Runners
              </div>
              <div className="mt-1 flex items-center gap-1.5">
                <Cpu className="h-3.5 w-3.5 text-zinc-500" />
                <span className="font-mono text-base font-semibold text-white tabular-nums">
                  {canReadRunners
                    ? `${activeRunners}/${data.runners.length}`
                    : "Restricted"}
                </span>
              </div>
            </Link>
          </div>
        </Panel>
      </div>

      {/* Category Breakdown & Historical Trend Row (Symmetric 6 + 6 Grid) */}
      <div className="grid gap-5 lg:grid-cols-12">
        <Panel className="flex flex-col justify-between lg:col-span-6">
          <div>
            <SectionHeader
              title="Open Findings by Discipline"
              description="Distribution across all 6 core VAPT & AppSec testing domains."
              action={
                <Badge tone="neutral" className="tabular-nums">
                  {metrics.activeDisciplineCount}/6 active
                </Badge>
              }
            />

            <div className="space-y-2">
              {metrics.disciplineRows.map((disc) => {
                const Icon = disc.icon;
                const sharePct =
                  metrics.openCount > 0
                    ? Math.round((disc.count / metrics.openCount) * 100)
                    : 0;
                const barWidthPct =
                  disc.count > 0
                    ? Math.max(8, Math.round((disc.count / maxDisciplineCount) * 100))
                    : 0;

                return (
                  <Link
                    key={disc.key}
                    href={`/organizations/${orgId}/findings?category=${disc.key}`}
                    className="group flex items-center justify-between gap-3 rounded-xl border border-white/[0.055] bg-[#101013] px-3.5 py-2.5 transition hover:border-white/[0.14] hover:bg-[#16161b]"
                  >
                    <div className="flex w-44 shrink-0 items-center gap-2.5 sm:w-52">
                      <span
                        className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border ${
                          disc.count > 0
                            ? "border-white/[0.1] bg-[#18181f] text-zinc-200"
                            : "border-white/[0.05] bg-[#131317] text-zinc-500"
                        }`}
                      >
                        <Icon className="h-3.5 w-3.5" />
                      </span>
                      <div className="min-w-0">
                        <div className="truncate text-xs font-medium text-zinc-100 group-hover:text-white">
                          {disc.label}
                        </div>
                        <div className="font-mono text-[10px] text-zinc-500">
                          {disc.shortLabel}
                        </div>
                      </div>
                    </div>

                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/[0.05]">
                      <div
                        style={{ width: `${barWidthPct}%` }}
                        className={`h-full rounded-full transition-all ${
                          disc.critHigh > 0 ? "bg-rose-500" : "bg-[#2f71e3]"
                        }`}
                      />
                    </div>

                    <div className="flex w-20 shrink-0 items-center justify-end gap-2 font-mono tabular-nums">
                      <span className="text-[11px] text-zinc-500">{sharePct}%</span>
                      <span
                        className={`w-6 text-right text-xs font-semibold ${
                          disc.count > 0 ? "text-zinc-100" : "text-zinc-500"
                        }`}
                      >
                        {disc.count}
                      </span>
                    </div>
                  </Link>
                );
              })}
            </div>
          </div>
        </Panel>

        <Panel className="flex flex-col justify-between lg:col-span-6">
          <div>
            <SectionHeader
              title="Risk Observation Timeline"
              description="14-day daily observation velocity segmented by finding severity."
              action={
                <Badge tone="info" dot className="tabular-nums">
                  14-Day Window
                </Badge>
              }
            />

            <div className="space-y-3">
              {/* Top Timeline Summary & Severity Legend Bar */}
              <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-white/[0.068] bg-[#101013] px-3.5 py-2.5 text-xs">
                <div className="flex items-center gap-3 font-mono tabular-nums">
                  <span className="text-zinc-400">
                    Observed:{" "}
                    <strong className="text-zinc-100">{windowObservedTotal}</strong>
                  </span>
                  <span className="text-zinc-700">·</span>
                  <span className="text-zinc-400">
                    Peak:{" "}
                    <strong className="text-zinc-100">
                      {peakTimelineDay ? `${peakTimelineDay.total}` : "0"}
                    </strong>
                    {peakTimelineDay && peakTimelineDay.total > 0
                      ? ` (${peakTimelineDay.shortDate})`
                      : ""}
                  </span>
                </div>

                <div className="flex items-center gap-2.5 text-[11px] text-zinc-400">
                  <span className="inline-flex items-center gap-1">
                    <span className="h-2 w-2 rounded-full bg-rose-500" />
                    Crit
                  </span>
                  <span className="inline-flex items-center gap-1">
                    <span className="h-2 w-2 rounded-full bg-orange-500" />
                    High
                  </span>
                  <span className="inline-flex items-center gap-1">
                    <span className="h-2 w-2 rounded-full bg-amber-400" />
                    Med
                  </span>
                  <span className="inline-flex items-center gap-1">
                    <span className="h-2 w-2 rounded-full bg-[#2f71e3]" />
                    Low
                  </span>
                </div>
              </div>

              {/* Continuous 14-Column Severity-Stacked Chart with Dedicated X-Axis Rail */}
              <div className="rounded-xl border border-white/[0.068] bg-[#101013] p-4">
                <div className="relative h-44">
                  {/* Horizontal Reference Gridlines & Y-Axis Scale */}
                  <div className="pointer-events-none absolute inset-0 flex flex-col justify-between pb-6">
                    {[
                      maxTimelineCount,
                      Math.max(1, Math.round(maxTimelineCount / 2)),
                      0,
                    ].map((tick, idx) => (
                      <div key={idx} className="flex items-center gap-2">
                        <span className="w-5 text-right font-mono text-[10px] text-zinc-600 tabular-nums">
                          {tick}
                        </span>
                        <div className="h-px flex-1 border-b border-dashed border-white/[0.05]" />
                      </div>
                    ))}
                  </div>

                  {/* 14 Daily Columns + Dedicated Non-Overlapping Bottom X-Axis Labels */}
                  <div className="relative z-10 flex h-full flex-col justify-end pl-7">
                    <div className="grid h-36 grid-cols-[repeat(14,minmax(0,1fr))] items-end gap-1.5 pb-1">
                      {metrics.timelineDays.map((day) => {
                        const heightPct =
                          day.total > 0
                            ? Math.max(
                                14,
                                Math.round((day.total / maxTimelineCount) * 100),
                              )
                            : 0;
                        const critShare =
                          day.total > 0 ? (day.critical / day.total) * 100 : 0;
                        const highShare =
                          day.total > 0 ? (day.high / day.total) * 100 : 0;
                        const medShare =
                          day.total > 0 ? (day.medium / day.total) * 100 : 0;
                        const lowShare =
                          day.total > 0 ? (day.lowInfo / day.total) * 100 : 0;

                        return (
                          <div
                            key={day.dateKey}
                            title={`${day.dateKey}: ${day.total} findings (${day.critical} critical, ${day.high} high, ${day.medium} medium, ${day.lowInfo} low/info)`}
                            className="group flex h-full flex-col items-center justify-end gap-1"
                          >
                            <span
                              className={`font-mono text-[10px] tabular-nums leading-none ${
                                day.total > 0
                                  ? "font-semibold text-zinc-200"
                                  : "text-transparent select-none"
                              }`}
                            >
                              {day.total}
                            </span>

                            <div className="flex h-28 w-full items-end justify-center">
                              {day.total > 0 ? (
                                <div
                                  style={{ height: `${heightPct}%` }}
                                  className="flex w-full max-w-[20px] flex-col overflow-hidden rounded-t-md shadow-[0_0_12px_rgba(47,113,227,0.18)] transition-all group-hover:brightness-110"
                                >
                                  {critShare > 0 && (
                                    <div
                                      style={{ height: `${critShare}%` }}
                                      className="w-full bg-rose-500"
                                    />
                                  )}
                                  {highShare > 0 && (
                                    <div
                                      style={{ height: `${highShare}%` }}
                                      className="w-full bg-orange-500"
                                    />
                                  )}
                                  {medShare > 0 && (
                                    <div
                                      style={{ height: `${medShare}%` }}
                                      className="w-full bg-amber-400"
                                    />
                                  )}
                                  {lowShare > 0 && (
                                    <div
                                      style={{ height: `${lowShare}%` }}
                                      className="w-full bg-[#2f71e3]"
                                    />
                                  )}
                                </div>
                              ) : (
                                <div className="h-1 w-full max-w-[16px] rounded-full bg-white/[0.06] transition group-hover:bg-white/[0.15]" />
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>

                    {/* Dedicated Single-Line X-Axis Date Rail (7 Even Ticks — Never Wraps or Collides) */}
                    <div className="flex items-center justify-between border-t border-white/[0.06] pt-2">
                      {metrics.timelineDays
                        .filter((_, idx) => idx % 2 === 1)
                        .map((day) => (
                          <span
                            key={day.dateKey}
                            className={`whitespace-nowrap font-mono text-[10px] leading-none tabular-nums ${
                              day.total > 0
                                ? "font-semibold text-zinc-200"
                                : "text-zinc-500"
                            }`}
                          >
                            {day.shortDate.replace("-", "/")}
                          </span>
                        ))}
                    </div>
                  </div>
                </div>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-2 px-0.5 text-[11px] text-zinc-500">
                <span>
                  Derived from persisted{" "}
                  <code className="font-mono text-zinc-400">first_seen_at</code>{" "}
                  finding telemetry.
                </span>
                <span className="font-mono text-[10px] text-zinc-500 tabular-nums">
                  {metrics.timelineDays[0]?.dateKey} →{" "}
                  {metrics.timelineDays[metrics.timelineDays.length - 1]?.dateKey}
                </span>
              </div>
            </div>
          </div>
        </Panel>
      </div>

      {/* Recent Scan Activity & Audit Stream */}
      <div className="grid gap-5 lg:grid-cols-12">
        <Panel className="lg:col-span-6">
          <SectionHeader
            title="Recent Scan Activity"
            description="Latest orchestrated scan runs across authorized targets."
            action={
              canReadScans && (
                <Link
                  href={`/organizations/${orgId}/scans`}
                  className="inline-flex items-center gap-1 text-xs font-medium text-blue-400 hover:text-blue-300"
                >
                  All Scans <ArrowRight className="h-3 w-3" />
                </Link>
              )
            }
          />
          {!canReadScans ? (
            <NoticeBanner
              tone="info"
              message="Scan run history requires scan:read permission."
            />
          ) : scopedScans.length === 0 ? (
            <EmptyState
              icon={<Radar className="h-5 w-5" />}
              title="No scan runs executed yet"
              description="Create an asset, obtain an approved testing authorization, and queue a scan from the Scan Center."
              actionLabel="Go to Scan Center"
              actionHref={`/organizations/${orgId}/scans`}
            />
          ) : (
            <div className="space-y-2">
              {scopedScans.slice(0, 6).map((scan) => (
                <Link
                  key={scan.id}
                  href={`/organizations/${orgId}/scans/${scan.id}`}
                  className="group flex items-center justify-between gap-3 rounded-xl border border-white/[0.068] bg-[#101013] px-3.5 py-2.5 text-xs transition hover:border-white/[0.14] hover:bg-[#16161b]"
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <Radar className="h-3.5 w-3.5 shrink-0 text-zinc-500 group-hover:text-[#5b8ef8]" />
                      <span className="font-mono font-medium text-zinc-100">
                        {scan.id.slice(0, 8)}
                      </span>
                      <span className="truncate text-zinc-400">
                        ·{" "}
                        {projectNames.get(scan.project_id) ??
                          scan.project_id.slice(0, 8)}
                      </span>
                    </div>
                    <div className="mt-0.5 text-[11px] text-zinc-500 tabular-nums">
                      {formatUtc(scan.created_at)}
                    </div>
                  </div>
                  <div className="flex shrink-0 items-center gap-1.5">
                    <StatusBadge status={scan.status} />
                    <ArrowRight className="h-3.5 w-3.5 text-zinc-600 transition group-hover:text-zinc-300" />
                  </div>
                </Link>
              ))}
            </div>
          )}
        </Panel>

        <Panel className="lg:col-span-6">
          <SectionHeader
            title="Recent Security Audit Events"
            description="Append-only immutable audit trail for tenant control-plane actions."
            action={
              canReadAudit && (
                <Link
                  href={`/organizations/${orgId}/audit`}
                  className="inline-flex items-center gap-1 text-xs font-medium text-blue-400 hover:text-blue-300"
                >
                  Full Log <ArrowRight className="h-3 w-3" />
                </Link>
              )
            }
          />
          {!canReadAudit ? (
            <NoticeBanner
              tone="info"
              message="Audit logs require audit:read permission."
            />
          ) : data.auditEvents.length === 0 ? (
            <EmptyState
              icon={<Lock className="h-5 w-5" />}
              title="No audit events recorded"
              description="Administrative actions, authorizations, and scans write immutable audit entries here."
            />
          ) : (
            <div className="space-y-2">
              {data.auditEvents.map((ev) => (
                <div
                  key={ev.id}
                  className="flex items-start justify-between gap-3 rounded-lg border border-white/[0.068] bg-[#0e0e11] px-3 py-2 text-xs"
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <Activity className="h-3.5 w-3.5 shrink-0 text-zinc-500" />
                      <span className="truncate font-mono font-medium text-zinc-200">
                        {ev.action}
                      </span>
                    </div>
                    <div className="mt-0.5 text-[11px] text-zinc-500">
                      {ev.resource_type ? `${ev.resource_type} · ` : ""}
                      {formatUtc(ev.created_at)}
                    </div>
                  </div>
                  <StatusBadge status={ev.outcome} />
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>
      </div>

      {/* VForge Right Overview Inspector Rail */}
      <aside className="w-full shrink-0 xl:sticky xl:top-[69px] xl:w-72 xl:self-start xl:max-h-[calc(100vh-5.5rem)] xl:overflow-y-auto xl:will-change-transform">
        <div className="vf-surface rounded-2xl p-2">
          <div className="px-3 py-2 text-[11px] font-medium text-zinc-500">
            Workspace Overview
          </div>
          <div className="grid grid-cols-1 gap-0.5 sm:grid-cols-2 xl:grid-cols-1">
            <Link
              href={`/organizations/${orgId}/projects`}
              className="flex items-center justify-between rounded-lg px-3 py-2 text-[13px] text-zinc-300 transition hover:bg-white/[0.05] hover:text-white"
            >
              <span className="flex items-center gap-2.5">
                <FolderKanban className="h-4 w-4 text-zinc-500" />
                <span>Projects</span>
              </span>
              <span className="text-xs text-zinc-500 tabular-nums">
                {projects.length}
              </span>
            </Link>
            {canReadAssets ? (
              <Link
                href={`/organizations/${orgId}/assets`}
                className="flex items-center justify-between rounded-lg px-3 py-2 text-[13px] text-zinc-300 transition hover:bg-white/[0.05] hover:text-white"
              >
                <span className="flex items-center gap-2.5">
                  <Server className="h-4 w-4 text-zinc-500" />
                  <span>Targets &amp; Assets</span>
                </span>
                <span className="text-xs text-zinc-500 tabular-nums">
                  {data.assetsTotal}
                </span>
              </Link>
            ) : null}
            {canReadAuthz ? (
              <Link
                href={`/organizations/${orgId}/authorizations`}
                className="flex items-center justify-between rounded-lg px-3 py-2 text-[13px] text-zinc-300 transition hover:bg-white/[0.05] hover:text-white"
              >
                <span className="flex items-center gap-2.5">
                  <ShieldCheck className="h-4 w-4 text-zinc-500" />
                  <span>Approved Targets</span>
                </span>
                <span className="text-xs text-zinc-500 tabular-nums">
                  {approvedAssetCount}
                </span>
              </Link>
            ) : null}
            {canReadScans ? (
              <Link
                href={`/organizations/${orgId}/scans`}
                className="flex items-center justify-between rounded-lg px-3 py-2 text-[13px] text-zinc-300 transition hover:bg-white/[0.05] hover:text-white"
              >
                <span className="flex items-center gap-2.5">
                  <Radar className="h-4 w-4 text-zinc-500" />
                  <span>Scan Runs</span>
                </span>
                <span className="text-xs text-zinc-500 tabular-nums">
                  {scopedScans.length}
                </span>
              </Link>
            ) : null}
            {canReadFindings ? (
              <Link
                href={`/organizations/${orgId}/findings`}
                className="flex items-center justify-between rounded-lg px-3 py-2 text-[13px] text-zinc-300 transition hover:bg-white/[0.05] hover:text-white"
              >
                <span className="flex items-center gap-2.5">
                  <Bug className="h-4 w-4 text-zinc-500" />
                  <span>Open Issues</span>
                </span>
                <span className="text-xs text-zinc-500 tabular-nums">
                  {metrics.openCount}
                </span>
              </Link>
            ) : null}
            {canReadScans ? (
              <Link
                href={`/organizations/${orgId}/evidence`}
                className="flex items-center justify-between rounded-lg px-3 py-2 text-[13px] text-zinc-300 transition hover:bg-white/[0.05] hover:text-white"
              >
                <span className="flex items-center gap-2.5">
                  <FileArchive className="h-4 w-4 text-zinc-500" />
                  <span>Evidence Vault</span>
                </span>
                <ArrowRight className="h-3.5 w-3.5 text-zinc-600" />
              </Link>
            ) : null}
            {canReadAudit ? (
              <Link
                href={`/organizations/${orgId}/audit`}
                className="flex items-center justify-between rounded-lg px-3 py-2 text-[13px] text-zinc-300 transition hover:bg-white/[0.05] hover:text-white"
              >
                <span className="flex items-center gap-2.5">
                  <ScrollText className="h-4 w-4 text-zinc-500" />
                  <span>Audit Log</span>
                </span>
                <span className="text-xs text-zinc-500 tabular-nums">
                  {data.auditEvents.length}
                </span>
              </Link>
            ) : null}
          </div>

          <div className="my-1.5 border-t border-white/[0.06]" />

          <div className="space-y-0.5 px-3 py-1.5 text-xs">
            <div className="flex items-center justify-between py-1 text-zinc-500">
              <span className="flex items-center gap-2">
                <Cpu className="h-3.5 w-3.5" />
                <span>Online Runners</span>
              </span>
              <span className="text-zinc-300 tabular-nums">
                {canReadRunners
                  ? `${activeRunners}/${data.runners.length}`
                  : "Restricted"}
              </span>
            </div>
            <div className="flex items-center justify-between py-1 text-zinc-500">
              <span>CISA KEV Matches</span>
              <span className="text-zinc-300 tabular-nums">
                {data.intelSummary ? data.intelSummary.kev_findings_count : "—"}
              </span>
            </div>
            <div className="flex items-center justify-between py-1 text-zinc-500">
              <span>High EPSS Risk</span>
              <span className="text-zinc-300 tabular-nums">
                {data.intelSummary
                  ? data.intelSummary.high_epss_findings_count
                  : "—"}
              </span>
            </div>
          </div>
        </div>
      </aside>
    </div>
  );
}

export default function OrganizationDashboardPage() {
  const params = useParams<{ orgId: string }>();
  const orgId = params.orgId;

  return (
    <OrgShell orgId={orgId}>
      {({ membership }) => (
        <DashboardContent
          orgId={orgId}
          canReadAssets={hasPermission(membership, "asset:read")}
          canReadAuthz={hasPermission(membership, "authorization:read")}
          canReadScans={hasPermission(membership, "scan:read")}
          canReadFindings={hasPermission(membership, "finding:read")}
          canReadIntel={hasPermission(membership, "intel:read")}
          canReadRunners={hasPermission(membership, "runner:read")}
          canReadAudit={hasPermission(membership, "audit:read")}
          canManageSettings={hasPermission(membership, "org:update")}
        />
      )}
    </OrgShell>
  );
}
