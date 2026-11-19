"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import {
  Archive,
  Download,
  FileCode2,
  FileText,
  KeyRound,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";
import OrgShell, {
  hasPermission,
  useOrgWorkspaceContext,
} from "@/components/OrgShell";
import { Badge, StatusBadge } from "@/components/ui/Badge";
import { Panel, SectionHeader, StatCard } from "@/components/ui/Card";
import { PageHeader } from "@/components/ui/PageHeader";
import { EmptyState, NoticeBanner } from "@/components/ui/States";
import { DataTableWrapper, Td, Th } from "@/components/ui/Table";
import { apiFetch, formatUtc } from "@/lib/api";
import type {
  PaginatedResponse,
  ReportItem,
  RunnerArtifact,
  ScanRunSummary,
  ScopeSnapshot,
} from "@/lib/types";

interface EvidenceArtifactRow extends RunnerArtifact {
  scan_status: string;
  project_id: string;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function EvidenceContent({
  orgId,
  canReadScans,
  canReadSnapshots,
  canReadReports,
}: {
  orgId: string;
  canReadScans: boolean;
  canReadSnapshots: boolean;
  canReadReports: boolean;
}) {
  const workspaceCtx = useOrgWorkspaceContext();
  const selectedProjectId = workspaceCtx?.selectedProjectId ?? "all";

  const [artifacts, setArtifacts] = useState<EvidenceArtifactRow[]>([]);
  const [snapshots, setSnapshots] = useState<ScopeSnapshot[]>([]);
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadEvidence = useCallback(async () => {
    try {
      const [scansRes, snapshotsRes, reportsRes] = await Promise.all([
        canReadScans
          ? apiFetch<PaginatedResponse<ScanRunSummary>>(
              `/api/v1/organizations/${orgId}/scans?limit=20`,
            )
          : Promise.resolve({ items: [] as ScanRunSummary[], total: 0 }),
        canReadSnapshots
          ? apiFetch<PaginatedResponse<ScopeSnapshot>>(
              `/api/v1/organizations/${orgId}/snapshots?limit=50`,
            ).catch(() => ({ items: [] as ScopeSnapshot[], total: 0 }))
          : Promise.resolve({ items: [] as ScopeSnapshot[], total: 0 }),
        canReadReports
          ? apiFetch<PaginatedResponse<ReportItem>>(
              `/api/v1/organizations/${orgId}/reports?limit=20`,
            ).catch(() => ({ items: [] as ReportItem[], total: 0 }))
          : Promise.resolve({ items: [] as ReportItem[], total: 0 }),
      ]);

      const filteredScans =
        selectedProjectId === "all"
          ? scansRes.items
          : scansRes.items.filter((s) => s.project_id === selectedProjectId);

      const artifactLists = await Promise.all(
        filteredScans.slice(0, 10).map(async (scan) => {
          try {
            const list = await apiFetch<RunnerArtifact[]>(
              `/api/v1/organizations/${orgId}/scans/${scan.id}/artifacts`,
            );
            return list.map((art) => ({
              ...art,
              scan_status: scan.status,
              project_id: scan.project_id,
            }));
          } catch {
            return [] as EvidenceArtifactRow[];
          }
        }),
      );

      setArtifacts(artifactLists.flat());
      setSnapshots(
        selectedProjectId === "all"
          ? snapshotsRes.items
          : snapshotsRes.items.filter((s) => s.project_id === selectedProjectId),
      );
      setReports(
        selectedProjectId === "all"
          ? reportsRes.items
          : reportsRes.items.filter((r) => r.project_id === selectedProjectId),
      );
      setError(null);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to load evidence registry",
      );
    } finally {
      setLoading(false);
    }
  }, [
    orgId,
    selectedProjectId,
    canReadScans,
    canReadSnapshots,
    canReadReports,
  ]);

  useEffect(() => {
    let active = true;
    void Promise.resolve().then(() => {
      if (active) return loadEvidence();
    });
    return () => {
      active = false;
    };
  }, [loadEvidence]);

  if (loading) {
    return (
      <div className="space-y-4">
        <div className="h-24 animate-pulse rounded-xl border border-white/[0.068] bg-[#141417]" />
        <div className="h-56 animate-pulse rounded-xl border border-white/[0.068] bg-[#141417]" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Assurance & Cryptographic Proof"
        title="Evidence & Encrypted Artifacts"
        description="Consolidated view of AES-GCM envelope-encrypted scanner artifacts, Ed25519-signed authorization scope snapshots, and generated compliance reports."
        actions={
          <button
            type="button"
            onClick={() => {
              setLoading(true);
              void loadEvidence();
            }}
            className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.1] bg-[#111114] px-3 py-1.5 text-xs font-medium text-zinc-200 transition hover:bg-white/[0.06]"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Refresh
          </button>
        }
      />

      {error && <NoticeBanner tone="error" message={error} />}

      <div className="grid gap-4 sm:grid-cols-3">
        <StatCard
          label="Scan Output Artifacts"
          value={artifacts.length}
          sublabel="Envelope-encrypted JSON / SARIF / raw logs"
          icon={<Archive className="h-4 w-4 text-[#93c5fd]" />}
        />
        <StatCard
          label="Signed Scope Snapshots"
          value={snapshots.length}
          sublabel="Ed25519 immutable authorization proof"
          tone={snapshots.length > 0 ? "success" : "default"}
          icon={<KeyRound className="h-4 w-4 text-zinc-200" />}
        />
        <StatCard
          label="Generated Reports"
          value={reports.length}
          sublabel="Technical, compliance & executive outputs"
          icon={<FileText className="h-4 w-4 text-[#93c5fd]" />}
          href={canReadReports ? `/organizations/${orgId}/reports` : undefined}
        />
      </div>

      {/* Scan Artifacts Table */}
      <Panel>
        <SectionHeader
          title="Encrypted Scanner Output Artifacts"
          description="Artifacts produced by isolated execution runners from the latest 10 scan runs."
          action={
            <Link
              href={`/organizations/${orgId}/scans`}
              className="text-xs font-medium text-[#93c5fd] hover:text-[#93c5fd]"
            >
              Inspect All Scan Runs →
            </Link>
          }
        />
        {!canReadScans ? (
          <NoticeBanner
            tone="info"
            message="Viewing scan artifacts requires scan:read permission."
          />
        ) : artifacts.length === 0 ? (
          <EmptyState
            icon={<FileCode2 className="h-5 w-5" />}
            title="No scanner artifacts collected yet"
            description="Completed scan runs store envelope-encrypted SARIF, CycloneDX SBOM, and raw tool evidence here."
            actionLabel="Open Scan Center"
            actionHref={`/organizations/${orgId}/scans`}
          />
        ) : (
          <DataTableWrapper>
            <table className="min-w-full text-left text-xs">
              <thead>
                <tr>
                  <Th>Type</Th>
                  <Th>Scan Run</Th>
                  <Th>SHA-256 Digest</Th>
                  <Th>KEK Key ID</Th>
                  <Th>Size</Th>
                  <Th>Created</Th>
                  <Th className="text-right">Download</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.06]/80 text-zinc-300">
                {artifacts.map((art) => (
                  <tr key={art.id} className="hover:bg-white/[0.03]">
                    <Td>
                      <Badge tone="info">{art.artifact_type}</Badge>
                    </Td>
                    <Td className="font-mono">
                      <Link
                        href={`/organizations/${orgId}/scans/${art.scan_run_id}`}
                        className="text-[#93c5fd] hover:underline"
                      >
                        {art.scan_run_id.slice(0, 8)}
                      </Link>
                    </Td>
                    <Td className="font-mono text-[11px] text-zinc-400">
                      {art.sha256.slice(0, 16)}…
                    </Td>
                    <Td className="font-mono text-[11px] text-zinc-400">
                      {art.kek_key_id}
                    </Td>
                    <Td>{formatBytes(art.size_bytes)}</Td>
                    <Td className="whitespace-nowrap text-zinc-400">
                      {formatUtc(art.created_at)}
                    </Td>
                    <Td className="text-right">
                      <a
                        href={`/api/v1/organizations/${orgId}/scans/${art.scan_run_id}/artifacts/${art.id}/download`}
                        className="inline-flex items-center gap-1 vf-btn-secondary px-2.5 py-1 text-xs"
                      >
                        <Download className="h-3 w-3" />
                        Download
                      </a>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </DataTableWrapper>
        )}
      </Panel>

      {/* Signed Scope Snapshots */}
      <Panel>
        <SectionHeader
          title="Ed25519 Signed Scope Snapshots"
          description="Tamper-evident target authorization snapshots bound to scan runs."
          action={
            <Link
              href={`/organizations/${orgId}/scope`}
              className="text-xs font-medium text-[#93c5fd] hover:text-[#93c5fd]"
            >
              Verify in Scope Policy →
            </Link>
          }
        />
        {!canReadSnapshots ? (
          <NoticeBanner
            tone="info"
            message="Viewing signed scope snapshots requires snapshot:read permission."
          />
        ) : snapshots.length === 0 ? (
          <EmptyState
            icon={<ShieldCheck className="h-5 w-5" />}
            title="No signed scope snapshots issued yet"
            description="Create a signed scope snapshot on an approved authorization before dispatching a scan."
            actionLabel="Go to Scope Policy"
            actionHref={`/organizations/${orgId}/scope`}
          />
        ) : (
          <DataTableWrapper>
            <table className="min-w-full text-left text-xs">
              <thead>
                <tr>
                  <Th>Target Locator</Th>
                  <Th>Intensity</Th>
                  <Th>Signing Key</Th>
                  <Th>Payload Digest</Th>
                  <Th>Expires</Th>
                  <Th>Issued</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.06]/80 text-zinc-300">
                {snapshots.map((snap) => (
                  <tr key={snap.id} className="hover:bg-white/[0.03]">
                    <Td className="font-mono text-white">
                      {snap.canonical_locator}
                    </Td>
                    <Td>
                      <StatusBadge status={snap.permitted_intensity} />
                    </Td>
                    <Td className="font-mono text-[11px] text-zinc-200">
                      {snap.signing_key_id} ({snap.signature_algorithm})
                    </Td>
                    <Td className="font-mono text-[11px] text-zinc-400">
                      {snap.payload_sha256.slice(0, 16)}…
                    </Td>
                    <Td className="whitespace-nowrap text-zinc-400">
                      {formatUtc(snap.authorization_expires_at)}
                    </Td>
                    <Td className="whitespace-nowrap text-zinc-400">
                      {formatUtc(snap.created_at)}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </DataTableWrapper>
        )}
      </Panel>
    </div>
  );
}

export default function EvidencePage() {
  const params = useParams<{ orgId: string }>();
  const orgId = params.orgId;

  return (
    <OrgShell orgId={orgId}>
      {({ membership }) => {
        const canReadScans = hasPermission(membership, "scan:read");
        const canReadSnapshots = hasPermission(membership, "snapshot:read");
        const canReadReports = hasPermission(membership, "report:read");
        if (!canReadScans && !canReadSnapshots) {
          return (
            <NoticeBanner
              tone="error"
              title="Permission Restricted"
              message="Viewing evidence requires scan:read or snapshot:read permission."
            />
          );
        }
        return (
          <EvidenceContent
            orgId={orgId}
            canReadScans={canReadScans}
            canReadSnapshots={canReadSnapshots}
            canReadReports={canReadReports}
          />
        );
      }}
    </OrgShell>
  );
}
