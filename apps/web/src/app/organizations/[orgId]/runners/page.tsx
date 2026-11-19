"use client";

import { useParams } from "next/navigation";
import { FormEvent, useCallback, useEffect, useState } from "react";
import OrgShell, { hasPermission } from "@/components/OrgShell";
import { Select } from "@/components/ui/Select";
import { apiFetch, formatUtc } from "@/lib/api";
import type { RunnerEventItem, RunnerItem, RunnerPool } from "@/lib/types";

function RunnersContent({
  orgId,
  canManage,
  csrfToken,
}: {
  orgId: string;
  canManage: boolean;
  csrfToken: string | null;
}) {
  const [pools, setPools] = useState<RunnerPool[]>([]);
  const [runners, setRunners] = useState<RunnerItem[]>([]);
  const [events, setEvents] = useState<RunnerEventItem[]>([]);

  const [poolName, setPoolName] = useState("Isolated Org Pool");
  const [poolSlug, setPoolSlug] = useState("");
  const [poolType, setPoolType] = useState<"standard" | "dast_egress" | "airgapped">(
    "dast_egress",
  );
  const [maxConcurrency, setMaxConcurrency] = useState(2);

  const [regPoolId, setRegPoolId] = useState("");
  const [runnerName, setRunnerName] = useState("linux-runner-01");
  const [certPem, setCertPem] = useState("");

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const loadAll = useCallback(async () => {
    const [poolList, runnerList, eventList] = await Promise.all([
      apiFetch<RunnerPool[]>(`/api/v1/organizations/${orgId}/runner-pools`),
      apiFetch<RunnerItem[]>(`/api/v1/organizations/${orgId}/runners`),
      apiFetch<RunnerEventItem[]>(`/api/v1/organizations/${orgId}/runner-events?limit=50`),
    ]);
    return { poolList, runnerList, eventList };
  }, [orgId]);

  const reload = useCallback(async () => {
    try {
      const data = await loadAll();
      setPools(data.poolList);
      setRunners(data.runnerList);
      setEvents(data.eventList);
      if (data.poolList.length > 0) {
        setRegPoolId((prev) => prev || data.poolList[0].id);
      }
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load runner inventory");
    } finally {
      setLoading(false);
    }
  }, [loadAll]);

  useEffect(() => {
    let active = true;
    void loadAll()
      .then((data) => {
        if (!active) return;
        setPools(data.poolList);
        setRunners(data.runnerList);
        setEvents(data.eventList);
        if (data.poolList.length > 0) {
          setRegPoolId((prev) => prev || data.poolList[0].id);
        }
        setError(null);
      })
      .catch((err) => {
        if (!active) return;
        setError(err instanceof Error ? err.message : "Failed to load runner inventory");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [loadAll]);

  const handleCreatePool = async (evt: FormEvent) => {
    evt.preventDefault();
    setError(null);
    setNotice(null);
    try {
      const created = await apiFetch<RunnerPool>(
        `/api/v1/organizations/${orgId}/runner-pools`,
        {
          method: "POST",
          csrfToken,
          body: JSON.stringify({
            name: poolName,
            slug: poolSlug || `pool-${Date.now()}`,
            pool_type: poolType,
            max_concurrent_jobs: maxConcurrency,
          }),
        },
      );
      setPoolSlug("");
      setRegPoolId(created.id);
      setNotice(`Created runner pool ${created.name} (${created.slug}).`);
      await reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create runner pool");
    }
  };

  const handleRegisterRunner = async (evt: FormEvent) => {
    evt.preventDefault();
    setError(null);
    setNotice(null);
    try {
      const created = await apiFetch<RunnerItem>(
        `/api/v1/organizations/${orgId}/runners`,
        {
          method: "POST",
          csrfToken,
          body: JSON.stringify({
            pool_id: regPoolId,
            name: runnerName,
            certificate_pem: certPem,
            version: "0.1.0",
            capabilities: {
              network_profiles: ["none", "scoped-http-egress"],
            },
          }),
        },
      );
      setCertPem("");
      setNotice(`Registered mTLS runner ${created.name} (${created.runner_identity}).`);
      await reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to register runner certificate");
    }
  };

  const handleRevoke = async (runnerId: string) => {
    setError(null);
    setNotice(null);
    try {
      await apiFetch<RunnerItem>(
        `/api/v1/organizations/${orgId}/runners/${runnerId}/revoke`,
        {
          method: "POST",
          csrfToken,
          body: JSON.stringify({ reason: "Revoked by organization operator" }),
        },
      );
      setNotice(`Revoked mTLS runner ${runnerId.slice(0, 8)} — new requests fail closed.`);
      await reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke runner");
    }
  };

  if (loading) {
    return <p className="text-sm text-zinc-300">Loading isolated runner pools and mTLS fleet...</p>;
  }

  return (
    <div className="space-y-6">
      <div className="rounded-lg border border-[#3b72f2]/30 bg-[#121622] p-4 text-sm text-zinc-200">
        <div className="font-semibold text-zinc-200">
          Phase 4 Execution Plane: mTLS Runner Pools & Ephemeral Container Isolation
        </div>
        <p className="mt-1 text-xs text-zinc-200">
          Runners authenticate exclusively to the isolated TLS 1.3 mTLS Gateway using
          per-tenant SPIFFE X.509 certificates pinned by SHA-256 fingerprint, verify
          Ed25519-signed Execution Manifests, execute hardened rootless/read-only containers,
          and upload AES-256-GCM envelope-encrypted artifacts.
        </p>
      </div>

      {error && (
        <div className="rounded-md border border-white/[0.08] bg-[#131317] px-4 py-3 text-sm text-zinc-200">
          {error}
        </div>
      )}
      {notice && (
        <div className="rounded-md border border-white/[0.08] bg-[#121614] px-4 py-3 text-sm text-zinc-200">
          {notice}
        </div>
      )}

      {canManage && (
        <div className="grid gap-6 lg:grid-cols-2">
          <form
            onSubmit={handleCreatePool}
            className="space-y-3 rounded-lg border border-white/[0.068] bg-[#141417] p-5"
          >
            <h2 className="text-sm font-semibold text-white">Create Runner Pool</h2>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="text-xs text-zinc-300">
                Pool Name
                <input
                  value={poolName}
                  onChange={(e) => setPoolName(e.target.value)}
                  required
                  className="mt-1 vf-input"
                />
              </label>
              <label className="text-xs text-zinc-300">
                Slug
                <input
                  value={poolSlug}
                  onChange={(e) => setPoolSlug(e.target.value)}
                  placeholder="prod-isolated"
                  className="mt-1 vf-input"
                />
              </label>
              <label className="text-xs text-zinc-300">
                Pool Isolation Type
                <Select
                  value={poolType}
                  onChange={(e) =>
                    setPoolType(
                      e.target.value as "standard" | "dast_egress" | "airgapped",
                    )
                  }
                  className="mt-1"
                >
                  <option value="standard">standard</option>
                  <option value="dast_egress">dast_egress</option>
                  <option value="airgapped">airgapped</option>
                </Select>
              </label>
              <label className="text-xs text-zinc-300">
                Max Concurrent Jobs
                <input
                  type="number"
                  min={1}
                  max={64}
                  value={maxConcurrency}
                  onChange={(e) => setMaxConcurrency(Number(e.target.value))}
                  className="mt-1 vf-input"
                />
              </label>
            </div>
            <button
              type="submit"
              className="vf-btn-primary px-3 py-1.5 text-xs font-medium"
            >
              Create Pool
            </button>
          </form>

          <form
            onSubmit={handleRegisterRunner}
            className="space-y-3 rounded-lg border border-white/[0.068] bg-[#141417] p-5"
          >
            <h2 className="text-sm font-semibold text-white">Register Runner X.509 Certificate</h2>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="text-xs text-zinc-300">
                Target Pool
                <Select
                  value={regPoolId}
                  onChange={(e) => setRegPoolId(e.target.value)}
                  required
                  className="mt-1"
                >
                  <option value="">Select pool...</option>
                  {pools.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} ({p.pool_type})
                    </option>
                  ))}
                </Select>
              </label>
              <label className="text-xs text-zinc-300">
                Runner Name
                <input
                  value={runnerName}
                  onChange={(e) => setRunnerName(e.target.value)}
                  required
                  className="mt-1 vf-input"
                />
              </label>
            </div>
            <label className="block text-xs text-zinc-300">
              Public X.509 Certificate PEM (SAN must match spiffe://vforge/org/...)
              <textarea
                rows={3}
                value={certPem}
                onChange={(e) => setCertPem(e.target.value)}
                required
                placeholder="-----BEGIN CERTIFICATE-----..."
                className="mt-1 w-full rounded border border-white/[0.1] bg-[#0e0e11] px-2.5 py-1.5 font-mono text-xs text-white"
              />
            </label>
            <button
              type="submit"
              className="vf-btn-primary px-3 py-1.5 text-xs font-medium"
            >
              Register Runner
            </button>
          </form>
        </div>
      )}

      <section className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-5">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white">Registered Runners ({runners.length})</h2>
          <button
            type="button"
            onClick={() => void reload()}
            className="vf-btn-secondary px-2.5 py-1 text-xs"
          >
            Refresh
          </button>
        </div>
        <div className="mt-3 overflow-x-auto">
          <table className="min-w-full text-left text-xs">
            <thead className="border-b border-white/[0.068] uppercase text-zinc-400">
              <tr>
                <th className="py-2 pr-4">Name</th>
                <th className="py-2 pr-4">SPIFFE Identity</th>
                <th className="py-2 pr-4">Status</th>
                <th className="py-2 pr-4">Cert SHA-256</th>
                <th className="py-2 pr-4">Last Heartbeat</th>
                <th className="py-2 pr-4">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06] text-zinc-300">
              {runners.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-4 text-zinc-400">
                    No mTLS runners registered for this organization yet.
                  </td>
                </tr>
              ) : (
                runners.map((r) => (
                  <tr key={r.id}>
                    <td className="py-2 pr-4 font-medium text-white">{r.name}</td>
                    <td className="py-2 pr-4 font-mono text-[11px]">{r.runner_identity}</td>
                    <td className="py-2 pr-4">
                      <span
                        className={`rounded px-2 py-0.5 ${
                          r.status === "revoked"
                            ? "bg-[#19191f] text-rose-300 border border-white/[0.08]"
                            : "bg-[#1a1a1f] text-zinc-200 border border-white/[0.08]"
                        }`}
                      >
                        {r.status}
                      </span>
                    </td>
                    <td className="py-2 pr-4 font-mono">{r.cert_sha256.slice(0, 16)}...</td>
                    <td className="py-2 pr-4">{formatUtc(r.last_heartbeat_at)}</td>
                    <td className="py-2 pr-4">
                      {canManage && r.status !== "revoked" ? (
                        <button
                          type="button"
                          onClick={() => void handleRevoke(r.id)}
                          className="vf-btn-danger px-2 py-1"
                        >
                          Revoke
                        </button>
                      ) : (
                        <span className="text-zinc-500">-</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-5">
        <h2 className="text-sm font-semibold text-white">
          Append-Only Runner Security & Lifecycle Events ({events.length})
        </h2>
        <div className="mt-3 overflow-x-auto">
          <table className="min-w-full text-left text-xs">
            <thead className="border-b border-white/[0.068] uppercase text-zinc-400">
              <tr>
                <th className="py-2 pr-4">Timestamp</th>
                <th className="py-2 pr-4">Severity</th>
                <th className="py-2 pr-4">Event</th>
                <th className="py-2 pr-4">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06] text-zinc-300">
              {events.length === 0 ? (
                <tr>
                  <td colSpan={4} className="py-4 text-zinc-400">
                    No runner events recorded yet.
                  </td>
                </tr>
              ) : (
                events.map((ev) => (
                  <tr key={ev.id}>
                    <td className="py-2 pr-4">{formatUtc(ev.created_at)}</td>
                    <td className="py-2 pr-4">
                      <span
                        className={`rounded px-2 py-0.5 ${
                          ev.severity === "security"
                            ? "bg-[#19191f] text-zinc-200 border border-white/[0.08]"
                            : "bg-[#1c1c20] text-zinc-200"
                        }`}
                      >
                        {ev.severity}
                      </span>
                    </td>
                    <td className="py-2 pr-4 font-mono">{ev.event_type}</td>
                    <td className="py-2 pr-4 font-mono text-[11px] text-zinc-400">
                      {JSON.stringify(ev.details_json)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

export default function RunnersPage() {
  const params = useParams<{ orgId: string }>();

  return (
    <OrgShell orgId={params.orgId}>
      {({ auth, membership }) => {
        if (!hasPermission(membership, "runner:read")) {
          return (
            <div className="rounded-lg border border-white/[0.08] bg-[#131317] p-6 text-sm text-zinc-200">
              Your role does not have permission to inspect runner pools or mTLS fleet status.
            </div>
          );
        }
        return (
          <RunnersContent
            orgId={params.orgId}
            canManage={hasPermission(membership, "runner:manage")}
            csrfToken={auth.csrf_token}
          />
        );
      }}
    </OrgShell>
  );
}
