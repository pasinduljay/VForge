"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { FormEvent, useCallback, useEffect, useState } from "react";
import OrgShell, { hasPermission } from "@/components/OrgShell";
import { Select } from "@/components/ui/Select";
import { apiFetch, formatUtc } from "@/lib/api";
import {
  ASSET_TYPES,
  REGISTRATION_STATES,
  type Asset,
  type AssetType,
  type Environment,
  type PaginatedResponse,
  type Project,
  type RegistrationState,
} from "@/lib/types";

interface EnvOption {
  id: string;
  label: string;
}

function AssetsContent({
  orgId,
  canManage,
  csrfToken,
}: {
  orgId: string;
  canManage: boolean;
  csrfToken: string | null;
}) {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [total, setTotal] = useState(0);
  const [envOptions, setEnvOptions] = useState<EnvOption[]>([]);
  const [typeFilter, setTypeFilter] = useState<"" | AssetType>("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [environmentId, setEnvironmentId] = useState("");
  const [assetType, setAssetType] = useState<AssetType>("web_application");
  const [locator, setLocator] = useState("");
  const [notes, setNotes] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const fetchAssetsData = useCallback(async () => {
    const qs = typeFilter
      ? `?asset_type=${encodeURIComponent(typeFilter)}&limit=100`
      : "?limit=100";
    const [assetsRes, projRes] = await Promise.all([
      apiFetch<PaginatedResponse<Asset>>(`/api/v1/organizations/${orgId}/assets${qs}`),
      apiFetch<PaginatedResponse<Project>>(
        `/api/v1/organizations/${orgId}/projects?limit=100`,
      ),
    ]);
    const envLists = await Promise.all(
      projRes.items.map(async (proj) => {
        const envs = await apiFetch<PaginatedResponse<Environment>>(
          `/api/v1/organizations/${orgId}/projects/${proj.id}/environments?limit=100`,
        );
        return envs.items.map((env) => ({
          id: env.id,
          label: `${proj.name} / ${env.name} (${env.environment_type})`,
        }));
      }),
    );
    return { assetsRes, flattened: envLists.flat() };
  }, [orgId, typeFilter]);

  const load = useCallback(async () => {
    try {
      const { assetsRes, flattened } = await fetchAssetsData();
      setAssets(assetsRes.items);
      setTotal(assetsRes.total);
      setEnvOptions(flattened);
      if (flattened.length > 0) {
        setEnvironmentId((prev) => prev || flattened[0].id);
      }
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load assets");
    } finally {
      setLoading(false);
    }
  }, [fetchAssetsData]);

  useEffect(() => {
    let active = true;
    void fetchAssetsData()
      .then(({ assetsRes, flattened }) => {
        if (!active) return;
        setAssets(assetsRes.items);
        setTotal(assetsRes.total);
        setEnvOptions(flattened);
        if (flattened.length > 0) {
          setEnvironmentId((prev) => prev || flattened[0].id);
        }
        setError(null);
        setLoading(false);
      })
      .catch((err) => {
        if (!active) return;
        setError(err instanceof Error ? err.message : "Failed to load assets");
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [fetchAssetsData]);

  const handleRegister = async (e: FormEvent) => {
    e.preventDefault();
    if (!environmentId) {
      setError("Create a project and environment before registering an asset.");
      return;
    }
    setSubmitting(true);
    setError(null);
    setNotice(null);
    try {
      await apiFetch<Asset>(
        `/api/v1/organizations/${orgId}/environments/${environmentId}/assets`,
        {
          method: "POST",
          csrfToken,
          body: JSON.stringify({
            asset_type: assetType,
            locator: locator.trim(),
            scope_metadata: notes.trim() ? { notes: notes.trim() } : {},
            registration_state: "registered",
          }),
        },
      );
      setLocator("");
      setNotes("");
      setNotice("Asset registered and locator normalized. Note: registration alone does not authorize scanning.");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to register asset");
    } finally {
      setSubmitting(false);
    }
  };

  const handleStateChange = async (assetId: string, registrationState: RegistrationState) => {
    setError(null);
    setNotice(null);
    try {
      await apiFetch<Asset>(`/api/v1/organizations/${orgId}/assets/${assetId}`, {
        method: "PATCH",
        csrfToken,
        body: JSON.stringify({ registration_state: registrationState }),
      });
      setNotice("Asset registration state updated.");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update asset");
    }
  };

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="mb-1 text-[11px] font-semibold uppercase tracking-[0.12em] text-blue-400">
            Step 2 of 6 · Register Targets
          </div>
          <h1 className="text-2xl font-semibold text-white">Targets &amp; Assets ({total})</h1>
          <p className="mt-1 text-sm text-zinc-400">
            Add the URLs, domains, IPs, Git repos, or container images you want scanned. After adding one, head to Step 3 (Scan Approvals).
          </p>
        </div>
        <div className="w-full sm:w-48">
          <Select
            aria-label="Filter by asset type"
            size="sm"
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value as "" | AssetType)}
          >
            <option value="">All asset types</option>
            {ASSET_TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </Select>
        </div>
      </div>

      {error ? (
        <div className="rounded-md border border-white/[0.08] bg-[#131317] p-4 text-sm text-zinc-200">
          {error}
        </div>
      ) : null}
      {notice ? (
        <div className="rounded-md border border-white/[0.08] bg-[#121614] p-4 text-sm text-zinc-200">
          {notice}
        </div>
      ) : null}

      <section className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-6">
        {loading ? (
          <p className="text-sm text-zinc-400">Loading registered assets...</p>
        ) : assets.length === 0 ? (
          <p className="text-sm text-zinc-400">No assets registered yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-white/[0.068] text-xs uppercase text-zinc-400">
                <tr>
                  <th className="py-2 pr-4">Type</th>
                  <th className="py-2 pr-4">Normalized Locator</th>
                  <th className="py-2 pr-4">Environment</th>
                  <th className="py-2 pr-4">State</th>
                  <th className="py-2">Registered</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.06]">
                {assets.map((a) => {
                  const envLabel =
                    envOptions.find((e) => e.id === a.environment_id)?.label ||
                    a.environment_id;
                  return (
                    <tr key={a.id}>
                      <td className="py-3 pr-4 text-xs text-zinc-300">
                        <code>{a.asset_type}</code>
                      </td>
                      <td className="py-3 pr-4 font-mono text-xs text-zinc-200">
                        {a.normalized_locator}
                      </td>
                      <td className="py-3 pr-4 text-xs text-zinc-300">{envLabel}</td>
                      <td className="py-3 pr-4">
                        {canManage ? (
                          <div className="min-w-[130px]">
                            <Select
                              aria-label={`Registration state for ${a.normalized_locator}`}
                              size="sm"
                              value={a.registration_state}
                              onChange={(e) =>
                                void handleStateChange(
                                  a.id,
                                  e.target.value as RegistrationState,
                                )
                              }
                            >
                              {REGISTRATION_STATES.map((s) => (
                                <option key={s} value={s}>
                                  {s}
                                </option>
                              ))}
                            </Select>
                          </div>
                        ) : (
                          <span className="text-xs text-zinc-300">
                            {a.registration_state}
                          </span>
                        )}
                      </td>
                      <td className="py-3 text-xs text-zinc-400">
                        {formatUtc(a.created_at)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {canManage ? (
        <section className="rounded-xl border border-white/[0.068] bg-[#141417] p-6">
          <h2 className="text-lg font-medium text-white">Register Target Asset</h2>
          {notice && (
            <div className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-white/[0.08] bg-[#19191f] px-4 py-2.5 text-xs text-zinc-200">
              <span>Target saved. Before scanning, request testing authorization in Step 3.</span>
              <Link
                href={`/organizations/${orgId}/authorizations`}
                className="vf-btn-primary rounded-full px-3 py-1 text-xs"
              >
                Step 3: Scan Approvals →
              </Link>
            </div>
          )}
          {envOptions.length === 0 ? (
            <div className="mt-3 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-white/[0.08] bg-[#131317] px-4 py-3 text-sm text-zinc-200">
              <span>
                Create a project and environment first before registering target assets.
              </span>
              <Link
                href={`/organizations/${orgId}/projects`}
                className="vf-btn-primary rounded-full px-3.5 py-1.5 text-xs"
              >
                Step 1: Go to Projects →
              </Link>
            </div>
          ) : (
            <form onSubmit={handleRegister} className="mt-4 grid gap-4 sm:grid-cols-2">
              <div>
                <label className="block text-xs text-zinc-300">Environment</label>
                <Select
                  value={environmentId}
                  onChange={(e) => setEnvironmentId(e.target.value)}
                  className="mt-1"
                >
                  {envOptions.map((env) => (
                    <option key={env.id} value={env.id}>
                      {env.label}
                    </option>
                  ))}
                </Select>
              </div>
              <div>
                <label className="block text-xs text-zinc-300">Asset Type</label>
                <Select
                  value={assetType}
                  onChange={(e) => setAssetType(e.target.value as AssetType)}
                  className="mt-1"
                >
                  {ASSET_TYPES.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </Select>
              </div>
              <div>
                <label className="block text-xs text-zinc-300">
                  Target Locator (normalized server-side)
                </label>
                <input
                  type="text"
                  required
                  value={locator}
                  onChange={(e) => setLocator(e.target.value)}
                  placeholder="https://staging.example.com"
                  className="mt-1 vf-input"
                />
              </div>
              <div>
                <label className="block text-xs text-zinc-300">Scope Notes</label>
                <input
                  type="text"
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="Owned by platform security team"
                  className="mt-1 vf-input"
                />
              </div>
              <div className="sm:col-span-2">
                <button
                  type="submit"
                  disabled={submitting}
                  className="vf-btn-primary h-8 px-4 text-xs"
                >
                  {submitting ? "Registering..." : "Register Asset"}
                </button>
              </div>
            </form>
          )}
        </section>
      ) : null}
    </div>
  );
}

export default function AssetsPage() {
  const params = useParams<{ orgId: string }>();
  return (
    <OrgShell orgId={params.orgId}>
      {({ auth, membership }) => (
        <AssetsContent
          orgId={params.orgId}
          canManage={hasPermission(membership, "asset:manage")}
          csrfToken={auth.csrf_token}
        />
      )}
    </OrgShell>
  );
}
