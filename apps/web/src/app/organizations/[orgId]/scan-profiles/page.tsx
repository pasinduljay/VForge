"use client";

import { useParams } from "next/navigation";
import { FormEvent, useCallback, useEffect, useState } from "react";
import OrgShell, { hasPermission } from "@/components/OrgShell";
import { apiFetch, formatUtc } from "@/lib/api";
import {
  ALLOWED_ACTIVITIES,
  type PaginatedResponse,
  type ScanProfile,
} from "@/lib/types";

function ScanProfilesContent({
  orgId,
  canManage,
  csrfToken,
}: {
  orgId: string;
  canManage: boolean;
  csrfToken: string | null;
}) {
  const [profiles, setProfiles] = useState<ScanProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [name, setName] = useState("");
  const [stages, setStages] = useState<string[]>(["sast", "secrets", "passive_dast"]);
  const [passiveOnly, setPassiveOnly] = useState(true);
  const [maxConcurrency, setMaxConcurrency] = useState(2);
  const [rps, setRps] = useState(5);
  const [timeoutSeconds, setTimeoutSeconds] = useState(900);
  const [submitting, setSubmitting] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await apiFetch<PaginatedResponse<ScanProfile>>(
        `/api/v1/organizations/${orgId}/scan-profiles?limit=100`,
      );
      setProfiles(res.items);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load scan profiles");
    } finally {
      setLoading(false);
    }
  }, [orgId]);

  useEffect(() => {
    let active = true;
    void apiFetch<PaginatedResponse<ScanProfile>>(
      `/api/v1/organizations/${orgId}/scan-profiles?limit=100`,
    )
      .then((res) => {
        if (!active) return;
        setProfiles(res.items);
        setError(null);
        setLoading(false);
      })
      .catch((err) => {
        if (!active) return;
        setError(err instanceof Error ? err.message : "Failed to load scan profiles");
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [orgId]);

  const toggleStage = (stage: string) => {
    setStages((prev) =>
      prev.includes(stage) ? prev.filter((s) => s !== stage) : [...prev, stage],
    );
  };

  const handleCreate = async (e: FormEvent) => {
    e.preventDefault();
    if (stages.length === 0) {
      setError("Select at least one stage.");
      return;
    }
    setSubmitting(true);
    setError(null);
    setNotice(null);
    try {
      const created = await apiFetch<ScanProfile>(
        `/api/v1/organizations/${orgId}/scan-profiles`,
        {
          method: "POST",
          csrfToken,
          body: JSON.stringify({
            name: name.trim(),
            configuration: {
              stages,
              passive_only: passiveOnly,
              max_concurrency: maxConcurrency,
              request_rate_limit_rps: rps,
              timeout_seconds: timeoutSeconds,
              include_paths: [],
              exclude_paths: [],
            },
            status: "active",
          }),
        },
      );
      setNotice(`Scan profile '${created.name}' v${created.version} created.`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create scan profile");
    } finally {
      setSubmitting(false);
    }
  };

  const handleToggleStatus = async (profile: ScanProfile) => {
    setError(null);
    setNotice(null);
    const nextStatus = profile.status === "active" ? "deprecated" : "active";
    try {
      await apiFetch<ScanProfile>(
        `/api/v1/organizations/${orgId}/scan-profiles/${profile.id}`,
        {
          method: "PATCH",
          csrfToken,
          body: JSON.stringify({ status: nextStatus }),
        },
      );
      setNotice(`Profile ${profile.name} v${profile.version} set to ${nextStatus}.`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update scan profile");
    }
  };

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold text-white">
          Versioned Scan Profiles ({profiles.length})
        </h1>
        <p className="mt-1 text-sm text-zinc-400">
          Governance configuration templates only. Reusing a profile name creates
          an immutable incremented version. Scanner execution begins in Phase 5+.
        </p>
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
          <p className="text-sm text-zinc-400">Loading scan profiles...</p>
        ) : profiles.length === 0 ? (
          <p className="text-sm text-zinc-400">No scan profiles configured yet.</p>
        ) : (
          <div className="space-y-3">
            {profiles.map((p) => (
              <div
                key={p.id}
                className="flex flex-wrap items-center justify-between gap-4 rounded-lg border border-white/[0.068] bg-[#0e0e11] p-4"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-white">{p.name}</span>
                    <span className="rounded bg-[#1c1c20] px-2 py-0.5 text-xs text-zinc-200">
                      v{p.version}
                    </span>
                    <span className="rounded bg-[#1c1c20] px-2 py-0.5 text-xs text-zinc-300">
                      {p.status}
                    </span>
                  </div>
                  <p className="mt-1 text-xs text-zinc-400">
                    Stages: {p.configuration.stages.join(", ")} · Passive only:{" "}
                    {p.configuration.passive_only ? "yes" : "no"} · RPS:{" "}
                    {p.configuration.request_rate_limit_rps} · Timeout:{" "}
                    {p.configuration.timeout_seconds}s · Created{" "}
                    {formatUtc(p.created_at)}
                  </p>
                </div>
                {canManage ? (
                  <button
                    type="button"
                    onClick={() => void handleToggleStatus(p)}
                    className="vf-btn-secondary px-3 py-1 text-xs"
                  >
                    {p.status === "active" ? "Deprecate" : "Reactivate"}
                  </button>
                ) : null}
              </div>
            ))}
          </div>
        )}
      </section>

      {canManage ? (
        <section className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-6">
          <h2 className="text-lg font-medium text-white">
            Create / Publish New Profile Version
          </h2>
          <form onSubmit={handleCreate} className="mt-4 grid gap-4 sm:grid-cols-2">
            <div>
              <label className="block text-xs text-zinc-300">Profile Name</label>
              <input
                type="text"
                required
                minLength={2}
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="standard-web-passive"
                className="mt-1 vf-input"
              />
            </div>
            <div className="flex items-end gap-2 pb-2">
              <label className="flex items-center gap-2 text-sm text-zinc-200">
                <input
                  type="checkbox"
                  checked={passiveOnly}
                  onChange={(e) => setPassiveOnly(e.target.checked)}
                />
                Passive checks only
              </label>
            </div>
            <div>
              <label className="block text-xs text-zinc-300">Max Concurrency</label>
              <input
                type="number"
                min={1}
                max={16}
                value={maxConcurrency}
                onChange={(e) =>
                  setMaxConcurrency(Number.parseInt(e.target.value, 10) || 2)
                }
                className="mt-1 vf-input"
              />
            </div>
            <div>
              <label className="block text-xs text-zinc-300">Rate Limit (req/sec)</label>
              <input
                type="number"
                min={1}
                max={200}
                value={rps}
                onChange={(e) => setRps(Number.parseInt(e.target.value, 10) || 5)}
                className="mt-1 vf-input"
              />
            </div>
            <div>
              <label className="block text-xs text-zinc-300">Timeout (seconds)</label>
              <input
                type="number"
                min={60}
                max={14400}
                value={timeoutSeconds}
                onChange={(e) =>
                  setTimeoutSeconds(Number.parseInt(e.target.value, 10) || 900)
                }
                className="mt-1 vf-input"
              />
            </div>
            <div className="sm:col-span-2">
              <span className="block text-xs text-zinc-300">Stages</span>
              <div className="mt-2 flex flex-wrap gap-2">
                {ALLOWED_ACTIVITIES.map((stage) => {
                  const checked = stages.includes(stage);
                  return (
                    <label
                      key={stage}
                      className={`cursor-pointer rounded border px-2.5 py-1 text-xs ${
                        checked
                          ? "border-white/[0.08] bg-[#1a1a1f] text-zinc-200"
                          : "border-white/[0.1] bg-[#0e0e11] text-zinc-300"
                      }`}
                    >
                      <input
                        type="checkbox"
                        className="mr-1.5"
                        checked={checked}
                        onChange={() => toggleStage(stage)}
                      />
                      {stage}
                    </label>
                  );
                })}
              </div>
            </div>
            <div className="sm:col-span-2">
              <button
                type="submit"
                disabled={submitting}
                className="vf-btn-primary h-8 px-4 text-xs"
              >
                {submitting ? "Publishing..." : "Save Scan Profile"}
              </button>
            </div>
          </form>
        </section>
      ) : null}
    </div>
  );
}

export default function ScanProfilesPage() {
  const params = useParams<{ orgId: string }>();
  return (
    <OrgShell orgId={params.orgId}>
      {({ auth, membership }) => (
        <ScanProfilesContent
          orgId={params.orgId}
          canManage={hasPermission(membership, "scan_profile:manage")}
          csrfToken={auth.csrf_token}
        />
      )}
    </OrgShell>
  );
}
