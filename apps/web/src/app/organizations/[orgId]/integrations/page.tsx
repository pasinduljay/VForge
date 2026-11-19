"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import {
  ArrowRight,
  Bot,
  Database,
  GitPullRequest,
  MessageSquare,
  Plug,
  Radio,
  Ticket,
} from "lucide-react";
import OrgShell, { hasPermission } from "@/components/OrgShell";
import { Badge, StatusBadge } from "@/components/ui/Badge";
import { Panel, SectionHeader } from "@/components/ui/Card";
import { PageHeader } from "@/components/ui/PageHeader";
import { NoticeBanner } from "@/components/ui/States";
import { apiFetch, formatUtc } from "@/lib/api";
import type {
  AiGovernanceOverview,
  IntelSourceItem,
} from "@/lib/types";

const PLANNED_INTEGRATIONS = [
  {
    name: "Jira Cloud & Linear Ticketing",
    category: "Issue Tracking",
    icon: Ticket,
    description:
      "Bi-directional escalation of critical/high findings, SLA ticket syncing, and automated retest state transitions.",
  },
  {
    name: "Slack & Microsoft Teams Alerts",
    category: "ChatOps Webhooks",
    icon: MessageSquare,
    description:
      "Signed webhook alerts for scan completions, SLA breaches, and pending risk exception approval requests.",
  },
  {
    name: "SIEM & OpenTelemetry Stream",
    category: "Audit Forwarding",
    icon: Radio,
    description:
      "Continuous streaming of append-only tenant audit logs and security posture events to Splunk HEC or Datadog.",
  },
  {
    name: "GitHub / GitLab PR Checks",
    category: "CI/CD Gates",
    icon: GitPullRequest,
    description:
      "SARIF annotations and policy-gated pull-request status checks connected to source snapshots.",
  },
];

function IntegrationsContent({
  orgId,
  canReadIntel,
  canReadAi,
}: {
  orgId: string;
  canReadIntel: boolean;
  canReadAi: boolean;
}) {
  const [intelSources, setIntelSources] = useState<IntelSourceItem[]>([]);
  const [aiOverview, setAiOverview] = useState<AiGovernanceOverview | null>(
    null,
  );
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    try {
      const [sourcesRes, aiRes] = await Promise.all([
        canReadIntel
          ? apiFetch<IntelSourceItem[]>("/api/v1/intel/sources").catch(
              () => [] as IntelSourceItem[],
            )
          : Promise.resolve([] as IntelSourceItem[]),
        canReadAi
          ? apiFetch<AiGovernanceOverview>(
              `/api/v1/organizations/${orgId}/ai/overview`,
            ).catch(() => null)
          : Promise.resolve(null),
      ]);
      setIntelSources(sourcesRes);
      setAiOverview(aiRes);
      setError(null);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to load integrations",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, canReadIntel, canReadAi]);

  useEffect(() => {
    let active = true;
    void Promise.resolve().then(() => {
      if (active) return loadData();
    });
    return () => {
      active = false;
    };
  }, [loadData]);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Connectivity & Feeds"
        title="Integrations Hub"
        description="Inspect active backend threat-intelligence feeds and governed AI providers alongside planned external enterprise connectors."
      />

      {error && <NoticeBanner tone="error" message={error} />}

      {/* Threat Intelligence Connectors */}
      <Panel>
        <SectionHeader
          title="Threat Intelligence Feed Connectors"
          description="Live platform connectors persisted in PostgreSQL and synchronized through the Threat Intel workspace."
          action={
            canReadIntel && (
              <Link
                href={`/organizations/${orgId}/threat-intel`}
                className="inline-flex items-center gap-1 text-xs font-medium text-[#93c5fd] hover:text-[#93c5fd]"
              >
                Manage Feeds <ArrowRight className="h-3 w-3" />
              </Link>
            )
          }
        />
        {!canReadIntel ? (
          <NoticeBanner
            tone="info"
            message="Viewing threat intelligence connectors requires intel:read permission."
          />
        ) : loading ? (
          <div className="h-28 animate-pulse rounded-lg border border-white/[0.068] bg-[#0e0e11]/50" />
        ) : intelSources.length === 0 ? (
          <NoticeBanner
            tone="info"
            message="No threat intelligence connectors registered yet."
          />
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {intelSources.map((src) => (
              <div
                key={src.id}
                className="rounded-lg border border-white/[0.068] bg-[#0e0e11] p-4 text-xs space-y-2"
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Database className="h-4 w-4 text-[#93c5fd]" />
                    <span className="font-semibold text-white">{src.name}</span>
                  </div>
                  <Badge tone={src.is_active ? "success" : "neutral"}>
                    {src.is_active ? "Active" : "Paused"}
                  </Badge>
                </div>
                <div className="font-mono text-[11px] text-zinc-400">
                  Type: {src.source_type} · Slug: {src.slug}
                </div>
                <div className="text-[11px] text-zinc-500">
                  License: {src.license_name} · Updated {formatUtc(src.updated_at)}
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>

      {/* AI Provider Gateway */}
      <Panel>
        <SectionHeader
          title="Governed AI Runtime Providers"
          description="Data-retention gated model providers configured for tenant triage and RAG summarization."
          action={
            canReadAi && (
              <Link
                href={`/organizations/${orgId}/ai-governance`}
                className="inline-flex items-center gap-1 text-xs font-medium text-[#93c5fd] hover:text-[#93c5fd]"
              >
                Configure in AI Governance <ArrowRight className="h-3 w-3" />
              </Link>
            )
          }
        />
        {!canReadAi ? (
          <NoticeBanner
            tone="info"
            message="Viewing AI provider gateway settings requires ai:read permission."
          />
        ) : loading ? (
          <div className="h-24 animate-pulse rounded-lg border border-white/[0.068] bg-[#0e0e11]/50" />
        ) : !aiOverview || aiOverview.provider_configs.length === 0 ? (
          <NoticeBanner
            tone="info"
            message="No tenant AI provider configurations active yet. Configure retention-approved providers from the AI Governance workspace."
          />
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {aiOverview.provider_configs.map((cfg) => (
              <div
                key={cfg.id}
                className="rounded-lg border border-white/[0.068] bg-[#0e0e11] p-4 text-xs space-y-2"
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Bot className="h-4 w-4 text-purple-400" />
                    <span className="font-semibold text-white">
                      {cfg.display_name}
                    </span>
                  </div>
                  <StatusBadge status={cfg.is_enabled ? "active" : "disabled"} />
                </div>
                <div className="text-[11px] text-zinc-400">
                  Provider:{" "}
                  <strong className="text-zinc-200">{cfg.provider_class}</strong>
                  {" · "}Consent:{" "}
                  <strong className="text-zinc-200">
                    {cfg.retention_consent_approved ? "Approved" : "Pending"}
                  </strong>
                  {" · "}
                  {cfg.local_only_mode ? "Local-Only" : "External"}
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>

      {/* Planned Enterprise Connectors */}
      <Panel>
        <SectionHeader
          title="Planned Enterprise Connectors"
          description="External ticketing, ChatOps, SIEM forwarding, and CI/CD connectors tracked on the platform roadmap."
          action={<Badge tone="planned">Backend Planned</Badge>}
        />
        <NoticeBanner
          tone="planned"
          message="These external webhook and issue-tracker integrations do not yet have backend API endpoints or secret storage bindings. Shown here transparently without simulated configuration."
          className="mb-4"
        />
        <div className="grid gap-4 sm:grid-cols-2">
          {PLANNED_INTEGRATIONS.map((item) => {
            const Icon = item.icon;
            return (
              <div
                key={item.name}
                className="rounded-lg border border-dashed border-white/[0.068] bg-[#0e0e11]/40 p-4 text-xs space-y-2"
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 font-semibold text-zinc-200">
                    <Icon className="h-4 w-4 text-zinc-400" />
                    {item.name}
                  </div>
                  <Badge tone="planned">Planned</Badge>
                </div>
                <p className="text-zinc-400 leading-relaxed">
                  {item.description}
                </p>
                <div className="flex items-center gap-1.5 text-[11px] text-zinc-500">
                  <Plug className="h-3 w-3" />
                  Category: {item.category}
                </div>
              </div>
            );
          })}
        </div>
      </Panel>
    </div>
  );
}

export default function IntegrationsPage() {
  const params = useParams<{ orgId: string }>();
  const orgId = params.orgId;

  return (
    <OrgShell orgId={orgId}>
      {({ membership }) => (
        <IntegrationsContent
          orgId={orgId}
          canReadIntel={hasPermission(membership, "intel:read")}
          canReadAi={hasPermission(membership, "ai:read")}
        />
      )}
    </OrgShell>
  );
}
