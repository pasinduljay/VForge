"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import OrgShell, { hasPermission } from "@/components/OrgShell";
import { apiFetch, formatUtc } from "@/lib/api";
import type {
  PaginatedResponse,
  SbomDocumentDetailItem,
  SbomDocumentItem,
  VulnerabilityDbSnapshotItem,
} from "@/lib/types";

function SupplyChainContent({ orgId }: { orgId: string }) {
  const [sboms, setSboms] = useState<SbomDocumentItem[]>([]);
  const [selectedSbom, setSelectedSbom] = useState<SbomDocumentDetailItem | null>(null);
  const [dbSnapshots, setDbSnapshots] = useState<VulnerabilityDbSnapshotItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [snapshotsWarning, setSnapshotsWarning] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    try {
      const [sbomResult, dbResult] = await Promise.allSettled([
        apiFetch<PaginatedResponse<SbomDocumentItem>>(
          `/api/v1/organizations/${orgId}/sboms`,
        ),
        apiFetch<PaginatedResponse<VulnerabilityDbSnapshotItem>>(
          `/api/v1/organizations/${orgId}/vulnerability-db-snapshots`,
        ),
      ]);
      if (sbomResult.status === "rejected") {
        throw sbomResult.reason;
      }
      setSboms(sbomResult.value.items);
      if (dbResult.status === "fulfilled") {
        setDbSnapshots(dbResult.value.items);
        setSnapshotsWarning(null);
      } else {
        setDbSnapshots([]);
        setSnapshotsWarning(
          dbResult.reason instanceof Error
            ? dbResult.reason.message
            : "Failed to load offline vulnerability database snapshots",
        );
      }
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load supply chain inventory");
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

  const inspectSbom = async (sbomId: string) => {
    try {
      const detail = await apiFetch<SbomDocumentDetailItem>(
        `/api/v1/organizations/${orgId}/sboms/${sbomId}`,
      );
      setSelectedSbom(detail);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load SBOM components");
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-white">Supply Chain Inventory &amp; Offline DB</h1>
          <p className="text-xs text-zinc-400">
            Immutable CycloneDX/SPDX SBOM documents ({sboms.length}) and air-gapped Grype
            vulnerability DB snapshots ({dbSnapshots.length}).
          </p>
        </div>
        <button
          type="button"
          onClick={() => {
            setLoading(true);
            void loadData();
          }}
          className="vf-btn-secondary px-3 py-1.5 text-xs"
        >
          Refresh
        </button>
      </div>

      {error && (
        <div className="rounded border border-white/[0.08] bg-[#131317] px-4 py-2 text-xs text-zinc-200">
          {error}
        </div>
      )}

      {snapshotsWarning && (
        <div className="rounded border border-white/[0.08] bg-[#131317] px-4 py-2 text-xs text-zinc-200">
          Offline DB snapshots could not be refreshed: {snapshotsWarning}
        </div>
      )}

      {loading ? (
        <div className="text-xs text-zinc-400">Loading SBOM and vulnerability DB provenance...</div>
      ) : (
        <>
          <section className="rounded-2xl border border-white/[0.068] bg-[#141417]">
            <div className="border-b border-white/[0.068] px-4 py-3">
              <h2 className="text-sm font-semibold text-white">Generated SBOM Documents</h2>
            </div>
            {sboms.length === 0 ? (
              <div className="p-4 text-xs text-zinc-400">
                No SBOM documents have been generated yet. Run a profile with the{" "}
                <span className="font-mono text-zinc-200">sbom</span> or{" "}
                <span className="font-mono text-zinc-200">sca</span> stage.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full text-left text-xs">
                <thead className="border-b border-white/[0.068] uppercase text-zinc-400">
                  <tr>
                    <th className="px-4 py-2.5">Format</th>
                    <th className="px-4 py-2.5">Spec</th>
                    <th className="px-4 py-2.5">Components</th>
                    <th className="px-4 py-2.5">BOM SHA-256</th>
                    <th className="px-4 py-2.5">Tool</th>
                    <th className="px-4 py-2.5">Created</th>
                    <th className="px-4 py-2.5">Inspect</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.06] text-zinc-300">
                  {sboms.map((doc) => (
                    <tr key={doc.id} className="hover:bg-white/[0.06]/40">
                      <td className="px-4 py-2.5 font-mono text-zinc-200">{doc.sbom_format}</td>
                      <td className="px-4 py-2.5 font-mono">{doc.spec_version}</td>
                      <td className="px-4 py-2.5">{doc.component_count}</td>
                      <td className="px-4 py-2.5 font-mono text-zinc-400">
                        {doc.bom_sha256.slice(0, 16)}...
                      </td>
                      <td className="px-4 py-2.5 font-mono">
                        {doc.tool_id}@{doc.tool_version}
                      </td>
                      <td className="px-4 py-2.5 text-zinc-400">{formatUtc(doc.created_at)}</td>
                      <td className="px-4 py-2.5">
                        <button
                          type="button"
                          onClick={() => void inspectSbom(doc.id)}
                          className="vf-btn-secondary h-7 px-3 text-xs"
                        >
                          Components
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
                </table>
              </div>
            )}
          </section>

          {selectedSbom && (
            <section className="rounded-2xl border border-white/[0.1] bg-[#111114]/90 p-5 space-y-3 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="min-w-0">
                  <h3 className="text-sm font-semibold text-white">
                    {selectedSbom.sbom_format} ({selectedSbom.component_count} components)
                  </h3>
                  <p className="break-all font-mono text-zinc-400">
                    Scan {selectedSbom.scan_run_id} | SHA-256: {selectedSbom.bom_sha256}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedSbom(null)}
                  className="vf-btn-secondary h-7 px-3 text-xs"
                >
                  Close
                </button>
              </div>
              <div className="overflow-x-auto rounded border border-white/[0.08]">
                <table className="min-w-full text-left text-xs">
                  <thead className="border-b border-white/[0.068] uppercase text-zinc-400">
                    <tr>
                      <th className="px-3 py-2">Package</th>
                      <th className="px-3 py-2">Version</th>
                      <th className="px-3 py-2">Ecosystem</th>
                      <th className="px-3 py-2">PURL</th>
                      <th className="px-3 py-2">Findings</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/[0.06] text-zinc-300">
                    {selectedSbom.components_summary.map((comp, idx) => (
                      <tr key={`${comp.purl || comp.name}-${idx}`}>
                        <td className="px-3 py-2 font-medium text-white">{comp.name}</td>
                        <td className="px-3 py-2 font-mono">{comp.version}</td>
                        <td className="px-3 py-2 font-mono">{comp.ecosystem || "-"}</td>
                        <td className="px-3 py-2 font-mono text-zinc-400">
                          {comp.purl || "-"}
                        </td>
                        <td className="px-3 py-2">
                          {comp.purl ? (
                            <Link
                              href={`/organizations/${orgId}/findings?purl=${encodeURIComponent(comp.purl)}`}
                              className="text-zinc-200 hover:underline"
                            >
                              Filter findings
                            </Link>
                          ) : (
                            "-"
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          <section className="rounded-2xl border border-white/[0.068] bg-[#141417]">
            <div className="border-b border-white/[0.068] px-4 py-3">
              <h2 className="text-sm font-semibold text-white">
                Recorded Offline Vulnerability DB Snapshots
              </h2>
            </div>
            {dbSnapshots.length === 0 ? (
              <div className="p-4 text-xs text-zinc-400">
                No offline vulnerability DB snapshots recorded yet.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full text-left text-xs">
                <thead className="border-b border-white/[0.068] uppercase text-zinc-400">
                  <tr>
                    <th className="px-4 py-2.5">Tool</th>
                    <th className="px-4 py-2.5">Schema Version</th>
                    <th className="px-4 py-2.5">Built At</th>
                    <th className="px-4 py-2.5">Archive SHA-256</th>
                    <th className="px-4 py-2.5">Valid</th>
                    <th className="px-4 py-2.5">Recorded</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.06] text-zinc-300">
                  {dbSnapshots.map((snap) => (
                    <tr key={snap.id} className="hover:bg-white/[0.06]/40">
                      <td className="px-4 py-2.5 font-mono">{snap.tool_id}</td>
                      <td className="px-4 py-2.5 font-mono">{snap.schema_version}</td>
                      <td className="px-4 py-2.5 text-zinc-400">{formatUtc(snap.built_at)}</td>
                      <td className="px-4 py-2.5 font-mono text-zinc-400">
                        {snap.db_archive_sha256.slice(0, 16)}...
                      </td>
                      <td className="px-4 py-2.5 font-mono">
                        {snap.valid ? "valid" : "invalid"}
                      </td>
                      <td className="px-4 py-2.5 text-zinc-400">{formatUtc(snap.recorded_at)}</td>
                    </tr>
                  ))}
                </tbody>
                </table>
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
}

export default function OrganizationSupplyChainPage() {
  const params = useParams<{ orgId: string }>();
  const orgId = params.orgId;

  return (
    <OrgShell orgId={orgId}>
      {({ membership }) =>
        hasPermission(membership, "sbom:read") ? (
          <SupplyChainContent orgId={orgId} />
        ) : (
          <div className="rounded border border-white/[0.08] bg-[#131317] p-4 text-xs text-zinc-200">
            You do not have permission (sbom:read) to inspect SBOM inventory in this organization.
          </div>
        )
      }
    </OrgShell>
  );
}
