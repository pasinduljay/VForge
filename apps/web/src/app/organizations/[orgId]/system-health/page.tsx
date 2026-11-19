"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import {
  Activity,
  Cpu,
  KeyRound,
  Lock,
  RefreshCw,
  Server,
  ShieldCheck,
} from "lucide-react";
import OrgShell, { hasPermission } from "@/components/OrgShell";
import { Badge, StatusBadge } from "@/components/ui/Badge";
import { Panel, SectionHeader, StatCard } from "@/components/ui/Card";
import { PageHeader } from "@/components/ui/PageHeader";
import { NoticeBanner } from "@/components/ui/States";
import { DataTableWrapper, Td, Th } from "@/components/ui/Table";
import { apiFetch, formatUtc } from "@/lib/api";
import type {
  HardeningOverview,
  OrgThreatIntelSummary,
  PlatformMeta,
  RunnerItem,
} from "@/lib/types";

function SystemHealthContent({
  orgId,
  canReadHardening,
  canReadRunners,
  canReadIntel,
}: {
  orgId: string;
  canReadHardening: boolean;
  canReadRunners: boolean;
  canReadIntel: boolean;
}) {
  const [meta, setMeta] = useState<PlatformMeta | null>(null);
  const [hardening, setHardening] = useState<HardeningOverview | null>(null);
  const [runners, setRunners] = useState<RunnerItem[]>([]);
  const [intel, setIntel] = useState<OrgThreatIntelSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadHealth = useCallback(async () => {
    try {
      const [metaRes, hardeningRes, runnersRes, intelRes] = await Promise.all([
        apiFetch<PlatformMeta>("/api/v1/meta"),
        canReadHardening
          ? apiFetch<HardeningOverview>(
              `/api/v1/organizations/${orgId}/hardening/overview`,
            ).catch(() => null)
          : Promise.resolve(null),
        canReadRunners
          ? apiFetch<RunnerItem[]>(
              `/api/v1/organizations/${orgId}/runners`,
            ).catch(() => [] as RunnerItem[])
          : Promise.resolve([] as RunnerItem[]),
        canReadIntel
          ? apiFetch<OrgThreatIntelSummary>(
              `/api/v1/organizations/${orgId}/intel/summary`,
            ).catch(() => null)
          : Promise.resolve(null),
      ]);
      setMeta(metaRes);
      setHardening(hardeningRes);
      setRunners(runnersRes);
      setIntel(intelRes);
      setError(null);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to load system health",
      );
    } finally {
      setLoading(false);
    }
  }, [orgId, canReadHardening, canReadRunners, canReadIntel]);

  useEffect(() => {
    let active = true;
    void Promise.resolve().then(() => {
      if (active) return loadHealth();
    });
    return () => {
      active = false;
    };
  }, [loadHealth]);

  if (loading && !meta) {
    return (
      <div className="space-y-4">
        <div className="h-24 animate-pulse rounded-xl border border-white/[0.068] bg-[#141417]" />
        <div className="h-48 animate-pulse rounded-xl border border-white/[0.068] bg-[#141417]" />
      </div>
    );
  }

  const activeRunners = runners.filter((r) => r.status === "active").length;
  const staleFeeds = (intel?.sources ?? []).filter((s) => s.is_stale);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Platform Diagnostics"
        title="System Health & Security Boundaries"
        description="Real-time control-plane runtime guarantees, mTLS runner certificate posture, RLS enforcement, and threat-feed freshness."
        actions={
          <button
            type="button"
            onClick={() => {
              setLoading(true);
              void loadHealth();
            }}
            className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.1] bg-[#111114] px-3 py-1.5 text-xs font-medium text-zinc-200 transition hover:bg-white/[0.06]"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Refresh
          </button>
        }
      />

      {error && <NoticeBanner tone="error" message={error} />}

      {meta && (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard
            label="Control Plane Build"
            value={`v${meta.version}`}
            sublabel={`Phase ${meta.phase} — ${meta.phase_name}`}
            tone="success"
            icon={<Server className="h-4 w-4 text-zinc-200" />}
          />
          <StatCard
            label="Docker Socket Isolation"
            value={meta.docker_socket_mounted ? "Mounted" : "Isolated"}
            sublabel="Control plane must never hold /var/run/docker.sock"
            tone={meta.docker_socket_mounted ? "danger" : "success"}
            icon={<Lock className="h-4 w-4 text-zinc-200" />}
          />
          <StatCard
            label="Runner Fleet Status"
            value={
              canReadRunners
                ? `${activeRunners}/${runners.length} Online`
                : meta.runner_connected
                  ? "Connected"
                  : "Standby"
            }
            sublabel={
              meta.scanners_enabled
                ? "Scanner dispatch enabled"
                : "Scanners in safe standby (disabled)"
            }
            tone={activeRunners > 0 ? "success" : "default"}
            icon={<Cpu className="h-4 w-4 text-[#93c5fd]" />}
            href={canReadRunners ? `/organizations/${orgId}/runners` : undefined}
          />
          <StatCard
            label="PostgreSQL RLS & OIDC"
            value={meta.oidc_enabled ? "OIDC Enforced" : "OIDC Disabled"}
            sublabel={
              hardening?.secret_and_runtime_posture.rls_forced_mode
                ? "FORCE ROW LEVEL SECURITY active"
                : "Control-plane auth boundary"
            }
            tone={meta.oidc_enabled ? "success" : "warning"}
            icon={<ShieldCheck className="h-4 w-4 text-zinc-200" />}
          />
        </div>
      )}

      {/* Runtime & Hardening Posture */}
      {hardening && (
        <div className="grid gap-6 lg:grid-cols-2">
          <Panel>
            <SectionHeader
              title="mTLS Certificate Posture"
              description={`Expiry warning threshold: ${hardening.certificate_posture.warning_threshold_days} days.`}
              action={
                <Link
                  href={`/organizations/${orgId}/security-ops`}
                  className="text-xs font-medium text-[#93c5fd] hover:text-[#93c5fd]"
                >
                  Open Security Ops →
                </Link>
              }
            />
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 text-xs">
              <div className="rounded-lg border border-white/[0.068] bg-[#0e0e11] p-3">
                <div className="text-zinc-400">Healthy</div>
                <div className="mt-1 text-lg font-semibold text-zinc-200">
                  {hardening.certificate_posture.healthy_count}
                </div>
              </div>
              <div className="rounded-lg border border-white/[0.068] bg-[#0e0e11] p-3">
                <div className="text-zinc-400">Expiring Soon</div>
                <div className="mt-1 text-lg font-semibold text-amber-300">
                  {hardening.certificate_posture.expiring_soon_count}
                </div>
              </div>
              <div className="rounded-lg border border-white/[0.068] bg-[#0e0e11] p-3">
                <div className="text-zinc-400">Expired</div>
                <div className="mt-1 text-lg font-semibold text-rose-300">
                  {hardening.certificate_posture.expired_count}
                </div>
              </div>
              <div className="rounded-lg border border-white/[0.068] bg-[#0e0e11] p-3">
                <div className="text-zinc-400">Revoked</div>
                <div className="mt-1 text-lg font-semibold text-zinc-300">
                  {hardening.certificate_posture.revoked_count}
                </div>
              </div>
            </div>
          </Panel>

          <Panel>
            <SectionHeader
              title="Cryptographic & Secret Runtime"
              description="Envelope encryption and secret-provider runtime telemetry."
            />
            <dl className="space-y-2 text-xs">
              <div className="flex items-center justify-between border-b border-white/[0.068]/70 pb-2">
                <dt className="text-zinc-400">Envelope Algorithm</dt>
                <dd className="font-mono text-white">
                  {hardening.crypto_agility.envelope_algorithm}
                </dd>
              </div>
              <div className="flex items-center justify-between border-b border-white/[0.068]/70 pb-2">
                <dt className="text-zinc-400">Active Artifact KEK</dt>
                <dd className="font-mono text-zinc-200">
                  {hardening.crypto_agility.active_artifact_kek_id}
                </dd>
              </div>
              <div className="flex items-center justify-between border-b border-white/[0.068]/70 pb-2">
                <dt className="text-zinc-400">Keyring Count / DR Runbook</dt>
                <dd className="font-mono text-zinc-200">
                  {hardening.crypto_agility.keyring_key_count} keys ·{" "}
                  {hardening.keys.length} tracked records
                </dd>
              </div>
              <div className="flex items-center justify-between">
                <dt className="text-zinc-400">FIPS / PQC Status</dt>
                <dd className="text-zinc-300">
                  {hardening.crypto_agility.fips_validated_claim
                    ? "FIPS Validated"
                    : "Non-FIPS (Honest Declaration)"}
                </dd>
              </div>
            </dl>
          </Panel>
        </div>
      )}

      {/* Registered Runners */}
      {canReadRunners && runners.length > 0 && (
        <Panel>
          <SectionHeader
            title="Registered Execution Runners"
            description="mTLS runner heartbeat and certificate health."
          />
          <DataTableWrapper>
            <table className="min-w-full text-left text-xs">
              <thead>
                <tr>
                  <Th>Runner Name</Th>
                  <Th>Status</Th>
                  <Th>Version</Th>
                  <Th>Last Heartbeat</Th>
                  <Th>Certificate Expiry</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.06]/80 text-zinc-300">
                {runners.map((runner) => (
                  <tr key={runner.id} className="hover:bg-white/[0.03]">
                    <Td className="font-medium text-white">{runner.name}</Td>
                    <Td>
                      <StatusBadge status={runner.status} />
                    </Td>
                    <Td className="font-mono">{runner.version}</Td>
                    <Td className="text-zinc-400">
                      {runner.last_heartbeat_at
                        ? formatUtc(runner.last_heartbeat_at)
                        : "Never"}
                    </Td>
                    <Td className="text-zinc-400">
                      {formatUtc(runner.cert_expires_at)}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </DataTableWrapper>
        </Panel>
      )}

      {/* Threat Feeds Health & Prometheus/Readiness Notice */}
      <div className="grid gap-6 lg:grid-cols-2">
        <Panel>
          <SectionHeader
            title="Threat Intelligence Feed Freshness"
            description="Status of KEV, EPSS, NVD, and OSV sync connectors."
          />
          {!canReadIntel || !intel ? (
            <NoticeBanner
              tone="info"
              message="Intel connector status requires intel:read permission."
            />
          ) : (
            <div className="space-y-2 text-xs">
              <div className="flex items-center justify-between text-zinc-300">
                <span>Configured Sources</span>
                <span className="font-mono">{intel.sources.length}</span>
              </div>
              <div className="flex items-center justify-between text-zinc-300">
                <span>Stale Feeds</span>
                <Badge tone={staleFeeds.length > 0 ? "warning" : "success"}>
                  {staleFeeds.length} stale
                </Badge>
              </div>
              {intel.sources.map((src) => (
                <div
                  key={src.id}
                  className="flex items-center justify-between rounded-lg border border-white/[0.068] bg-[#0e0e11] px-3 py-2"
                >
                  <div>
                    <div className="font-medium text-white">{src.name}</div>
                    <div className="text-[11px] text-zinc-400">
                      {src.records_persisted} records ·{" "}
                      {src.last_sync_at
                        ? `Last sync ${formatUtc(src.last_sync_at)}`
                        : "Not synced"}
                    </div>
                  </div>
                  <Badge tone={src.is_stale ? "warning" : "success"}>
                    {src.is_stale ? "Stale" : "Current"}
                  </Badge>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel className="space-y-3">
          <SectionHeader
            title="Prometheus & Infrastructure Probes"
            description="Operator-only observability endpoints."
          />
          <NoticeBanner
            tone="info"
            title="Operator Bearer Token Required for /metrics"
            message="FastAPI exposes Prometheus metrics at /metrics gated by METRICS_BEARER_TOKEN, and dependency readiness probes (PostgreSQL, RabbitMQ, Valkey, OPA) at /ready on the internal API origin. Browser clients do not query raw infrastructure sockets directly."
          />
          {meta && (
            <div className="rounded-lg border border-white/[0.068] bg-[#0e0e11] p-3 text-xs">
              <div className="mb-2 flex items-center gap-2 font-medium text-zinc-200">
                <Activity className="h-3.5 w-3.5 text-[#93c5fd]" />
                Active Control-Plane Capabilities (
                {meta.implemented_capabilities.length})
              </div>
              <div className="flex flex-wrap gap-1.5">
                {meta.implemented_capabilities.map((cap) => (
                  <span
                    key={cap}
                    className="rounded border border-white/[0.068] bg-[#141417] px-2 py-0.5 font-mono text-[10px] text-zinc-300"
                  >
                    {cap}
                  </span>
                ))}
              </div>
            </div>
          )}
          <div className="flex items-center gap-2 text-[11px] text-zinc-500">
            <KeyRound className="h-3.5 w-3.5" />
            <span>
              Tenant boundaries verified continuously via PostgreSQL FORCE ROW LEVEL SECURITY.
            </span>
          </div>
        </Panel>
      </div>
    </div>
  );
}

export default function SystemHealthPage() {
  const params = useParams<{ orgId: string }>();
  const orgId = params.orgId;

  return (
    <OrgShell orgId={orgId}>
      {({ membership }) => (
        <SystemHealthContent
          orgId={orgId}
          canReadHardening={hasPermission(membership, "hardening:read")}
          canReadRunners={hasPermission(membership, "runner:read")}
          canReadIntel={hasPermission(membership, "intel:read")}
        />
      )}
    </OrgShell>
  );
}
