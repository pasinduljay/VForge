"use client";

import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import OrgShell, { hasPermission } from "@/components/OrgShell";
import { Select } from "@/components/ui/Select";
import { apiFetch } from "@/lib/api";
import type {
  BackupManifestItem,
  EncryptionKeyRecordItem,
  HardeningOverview,
  KeyRewrapDrillItem,
  RestoreDrillItem,
} from "@/lib/types";

export default function SecurityOpsPage() {
  const params = useParams<{ orgId: string }>();
  const orgId = params.orgId;

  const [overview, setOverview] = useState<HardeningOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [newKeyId, setNewKeyId] = useState("vf-artifact-epoch-2");
  const [keyPurpose, setKeyPurpose] = useState<
    "artifact_envelope" | "backup_envelope" | "scope_signing" | "runner_mtls_ca"
  >("artifact_envelope");
  const [algoSuite, setAlgoSuite] = useState("aes-256-gcm-v1");
  const [pqcStatus, setPqcStatus] = useState<"classical_active" | "hybrid_planned" | "not_enabled">(
    "hybrid_planned",
  );
  const [keyFingerprint, setKeyFingerprint] = useState("");
  const [rewrapTargetId, setRewrapTargetId] = useState("vf-artifact-drill-2");
  const [rewrapResult, setRewrapResult] = useState<KeyRewrapDrillItem | null>(null);

  const loadData = useCallback(async () => {
    try {
      const data = await apiFetch<HardeningOverview>(
        `/api/v1/organizations/${orgId}/hardening/overview`,
      );
      setOverview(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load security hardening posture");
    } finally {
      setLoading(false);
    }
  }, [orgId]);

  useEffect(() => {
    let active = true;
    void apiFetch<HardeningOverview>(`/api/v1/organizations/${orgId}/hardening/overview`)
      .then((data) => {
        if (!active) return;
        setOverview(data);
        setError(null);
      })
      .catch((err) => {
        if (!active) return;
        setError(err instanceof Error ? err.message : "Failed to load security hardening posture");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [orgId]);

  return (
    <OrgShell orgId={orgId}>
      {({ auth, membership }) => {
        const canManage = hasPermission(membership, "hardening:manage");

        const handleRegisterKey = async () => {
          const cleanFp = keyFingerprint.trim().toLowerCase();
          if (!/^[0-9a-f]{64}$/.test(cleanFp)) {
            setError("key_fingerprint_sha256 must be 64 lowercase hexadecimal characters.");
            return;
          }
          setBusy(true);
          setStatusMessage(null);
          try {
            const created = await apiFetch<EncryptionKeyRecordItem>(
              `/api/v1/organizations/${orgId}/hardening/keys`,
              {
                method: "POST",
                csrfToken: auth.csrf_token,
                body: JSON.stringify({
                  key_id: newKeyId.trim(),
                  purpose: keyPurpose,
                  algorithm_suite: algoSuite.trim(),
                  pqc_readiness_status: pqcStatus,
                  cryptoperiod_days: 90,
                  key_fingerprint_sha256: cleanFp,
                  fips_validated_claim: false,
                  pqc_experimental_custom_protocol: false,
                }),
              },
            );
            setStatusMessage(
              `Registered key epoch ${created.key_id} (v${created.version}) for ${created.purpose}.`,
            );
            await loadData();
          } catch (err) {
            setError(err instanceof Error ? err.message : "Key registration failed");
          } finally {
            setBusy(false);
          }
        };

        const handleRewrapDrill = async () => {
          setBusy(true);
          setStatusMessage(null);
          try {
            const res = await apiFetch<KeyRewrapDrillItem>(
              `/api/v1/organizations/${orgId}/hardening/keys/rewrap-drill`,
              {
                method: "POST",
                csrfToken: auth.csrf_token,
                body: JSON.stringify({ new_kek_id: rewrapTargetId.trim() }),
              },
            );
            setRewrapResult(res);
            setStatusMessage(
              `AES-256-GCM DEK re-wrap drill passed: ${res.old_kek_id} -> ${res.new_kek_id}.`,
            );
            await loadData();
          } catch (err) {
            setError(err instanceof Error ? err.message : "Key re-wrap drill failed");
          } finally {
            setBusy(false);
          }
        };

        const handleCreateBackup = async () => {
          setBusy(true);
          setStatusMessage(null);
          try {
            const manifest = await apiFetch<BackupManifestItem>(
              `/api/v1/organizations/${orgId}/hardening/backups`,
              {
                method: "POST",
                csrfToken: auth.csrf_token,
                body: JSON.stringify({
                  backup_scope: "postgres_tenant_snapshot",
                  rpo_target_minutes: 60,
                  rto_target_minutes: 30,
                }),
              },
            );
            setStatusMessage(
              `Encrypted DR backup created (${manifest.size_bytes} B) under ${manifest.encryption_key_id}.`,
            );
            await loadData();
          } catch (err) {
            setError(err instanceof Error ? err.message : "Backup creation failed");
          } finally {
            setBusy(false);
          }
        };

        const handleRunDrill = async (manifestId: string) => {
          setBusy(true);
          setStatusMessage(null);
          try {
            const drill = await apiFetch<RestoreDrillItem>(
              `/api/v1/organizations/${orgId}/hardening/drills`,
              {
                method: "POST",
                csrfToken: auth.csrf_token,
                body: JSON.stringify({
                  manifest_id: manifestId,
                  drill_mode: "isolated_checksum_decrypt",
                }),
              },
            );
            setStatusMessage(
              `DR restore drill ${drill.status.toUpperCase()} (${drill.rto_observed_seconds}s) for manifest ${manifestId.slice(0, 8)}.`,
            );
            await loadData();
          } catch (err) {
            setError(err instanceof Error ? err.message : "Restore drill failed");
          } finally {
            setBusy(false);
          }
        };

        return (
          <div className="space-y-6">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <h1 className="text-2xl font-semibold text-white">
                  Security Hardening, Key Rotation & DR Operations
                </h1>
                <p className="mt-1 text-sm text-zinc-400">
                  Phase 14 — Envelope KEK lifecycle, PQC crypto-agility baselines, runner mTLS cert
                  expiry monitoring, encrypted DR backups & Prometheus observability.
                </p>
              </div>
              {canManage && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => void handleCreateBackup()}
                  className="vf-btn-primary h-8 px-4 text-xs"
                >
                  Create Encrypted Backup
                </button>
              )}
            </div>

            {error && (
              <div className="rounded-lg border border-white/[0.08] bg-[#131317] px-4 py-3 text-sm text-zinc-200">
                {error}
              </div>
            )}
            {statusMessage && (
              <div className="rounded-lg border border-white/[0.08] bg-[#121614] px-4 py-3 text-sm text-zinc-200">
                {statusMessage}
              </div>
            )}

            {loading || !overview ? (
              <div className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-6 text-sm text-zinc-300">
                Loading security hardening posture...
              </div>
            ) : (
              <>
                <div className="grid gap-4 md:grid-cols-4">
                  <div className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-4">
                    <div className="text-xs uppercase text-zinc-400">Envelope Algorithm</div>
                    <div className="mt-1 text-lg font-semibold text-white">
                      {overview.crypto_agility.envelope_algorithm}
                    </div>
                    <div className="mt-1 text-xs text-zinc-400">
                      KEK: {overview.crypto_agility.active_artifact_kek_id}
                    </div>
                  </div>
                  <div className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-4">
                    <div className="text-xs uppercase text-zinc-400">FIPS Validated Claim</div>
                    <div className="mt-1 text-lg font-semibold text-amber-300">
                      {overview.crypto_agility.fips_validated_claim ? "Yes" : "No (Honest Default)"}
                    </div>
                    <div className="mt-1 text-xs text-zinc-400">
                      Docker Socket:{" "}
                      {overview.secret_and_runtime_posture.docker_socket_mounted
                        ? "EXPOSED"
                        : "Isolated (Absent)"}
                    </div>
                  </div>
                  <div className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-4">
                    <div className="text-xs uppercase text-zinc-400">Runner mTLS Certs</div>
                    <div className="mt-1 text-lg font-semibold text-white">
                      {overview.certificate_posture.healthy_count} Healthy /{" "}
                      {overview.certificate_posture.expiring_soon_count} Expiring
                    </div>
                    <div className="mt-1 text-xs text-zinc-400">
                      Revoked: {overview.certificate_posture.revoked_count} | Expired:{" "}
                      {overview.certificate_posture.expired_count}
                    </div>
                  </div>
                  <div className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-4">
                    <div className="text-xs uppercase text-zinc-400">Secret Provider</div>
                    <div className="mt-1 text-lg font-semibold text-zinc-200">
                      {String(overview.secret_and_runtime_posture.secret_provider.provider || "n/a")}
                    </div>
                    <div className="mt-1 text-xs text-zinc-400">
                      Prometheus Metrics:{" "}
                      {overview.secret_and_runtime_posture.metrics_enabled ? "Enabled" : "Disabled"}
                    </div>
                  </div>
                </div>

                {/* Cryptography & PQC Agility Table */}
                <section className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-5">
                  <h2 className="text-base font-semibold text-white">
                    Cryptography Baseline & Post-Quantum Agility (§26)
                  </h2>
                  <p className="mt-1 text-xs text-amber-300">{overview.crypto_agility.fips_notice}</p>
                  <div className="mt-4 overflow-x-auto">
                    <table className="w-full text-left text-xs text-zinc-300">
                      <thead className="border-b border-white/[0.068] text-zinc-400">
                        <tr>
                          <th className="py-2 pr-4">Purpose</th>
                          <th className="py-2 pr-4">Classical Active</th>
                          <th className="py-2 pr-4">PQC Target</th>
                          <th className="py-2 pr-4">Standard</th>
                          <th className="py-2">PQC Live</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-white/[0.06]">
                        {overview.crypto_agility.profiles.map((prof) => (
                          <tr key={prof.purpose}>
                            <td className="py-2 pr-4 font-medium text-white">{prof.purpose}</td>
                            <td className="py-2 pr-4">{prof.classical_algorithm}</td>
                            <td className="py-2 pr-4">{prof.pqc_migration_target}</td>
                            <td className="py-2 pr-4">{prof.nist_standard}</td>
                            <td className="py-2">
                              {prof.pqc_live_enabled ? "Enabled" : "Migration Ready (Off)"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>

                {/* Key Epoch Rotation & Live Re-Wrap Drill */}
                {canManage && (
                  <section className="grid gap-4 md:grid-cols-2">
                    <div className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-5 space-y-3">
                      <h2 className="text-base font-semibold text-white">
                        Register / Rotate Key Epoch Metadata
                      </h2>
                      <div className="grid gap-2 sm:grid-cols-2 text-xs">
                        <input
                          value={newKeyId}
                          onChange={(e) => setNewKeyId(e.target.value)}
                          placeholder="Key ID"
                          className="rounded border border-white/[0.1] bg-[#0e0e11] px-3 py-2 text-zinc-200"
                        />
                        <Select
                          size="sm"
                          value={keyPurpose}
                          onChange={(e) =>
                            setKeyPurpose(
                              e.target.value as
                                | "artifact_envelope"
                                | "backup_envelope"
                                | "scope_signing"
                                | "runner_mtls_ca",
                            )
                          }
                        >
                          <option value="artifact_envelope">artifact_envelope</option>
                          <option value="backup_envelope">backup_envelope</option>
                          <option value="scope_signing">scope_signing</option>
                          <option value="runner_mtls_ca">runner_mtls_ca</option>
                        </Select>
                        <input
                          value={algoSuite}
                          onChange={(e) => setAlgoSuite(e.target.value)}
                          placeholder="Algorithm suite"
                          className="vf-input text-xs"
                        />
                        <Select
                          size="sm"
                          value={pqcStatus}
                          onChange={(e) =>
                            setPqcStatus(
                              e.target.value as
                                | "classical_active"
                                | "hybrid_planned"
                                | "not_enabled",
                            )
                          }
                        >
                          <option value="classical_active">classical_active</option>
                          <option value="hybrid_planned">hybrid_planned</option>
                          <option value="not_enabled">not_enabled</option>
                        </Select>
                        <input
                          value={keyFingerprint}
                          onChange={(e) => setKeyFingerprint(e.target.value)}
                          placeholder="Key SHA-256 fingerprint (64 hex chars)"
                          className="sm:col-span-2 rounded border border-white/[0.1] bg-[#0e0e11] px-3 py-2 font-mono text-zinc-200"
                        />
                      </div>
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => void handleRegisterKey()}
                        className="vf-btn-primary px-3.5 py-1.5 text-xs font-medium"
                      >
                        Register Key Epoch
                      </button>
                    </div>

                    <div className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-5 space-y-3">
                      <h2 className="text-base font-semibold text-white">
                        Live AES-256-GCM DEK Re-Wrap Drill
                      </h2>
                      <p className="text-xs text-zinc-400">
                        Wraps a payload under the active KEK, re-wraps its DEK onto a new target
                        KEK without re-encrypting data, and verifies decryption recovery.
                      </p>
                      <div className="flex flex-col gap-2 text-xs sm:flex-row">
                        <input
                          value={rewrapTargetId}
                          onChange={(e) => setRewrapTargetId(e.target.value)}
                          placeholder="Target New KEK ID"
                          className="vf-input flex-1 text-xs"
                        />
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => void handleRewrapDrill()}
                          className="vf-btn-primary h-8 px-4 text-xs"
                        >
                          Run Re-Wrap Drill
                        </button>
                      </div>
                      {rewrapResult && (
                        <div className="rounded border border-white/[0.08] bg-[#121614] p-2 text-xs text-zinc-200">
                          Verified {rewrapResult.old_kek_id} → {rewrapResult.new_kek_id} (SHA-256:{" "}
                          {rewrapResult.plaintext_sha256.slice(0, 12)}…)
                        </div>
                      )}
                    </div>
                  </section>
                )}

                {/* Encrypted DR Backup Manifests & Restore Drills */}
                <section className="grid gap-4 md:grid-cols-2">
                  <div className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-5">
                    <h2 className="text-base font-semibold text-white">
                      Encrypted DR Backup Manifests
                    </h2>
                    <div className="mt-3 space-y-2 text-xs">
                      {overview.backup_manifests.length === 0 ? (
                        <div className="text-zinc-400">No encrypted DR backups recorded yet.</div>
                      ) : (
                        overview.backup_manifests.map((m) => (
                          <div
                            key={m.id}
                            className="flex items-center justify-between gap-2 rounded border border-white/[0.068] bg-[#0e0e11]/70 p-3"
                          >
                            <div>
                              <div className="font-medium text-white">
                                {m.backup_scope} ({m.status})
                              </div>
                              <div className="text-zinc-400">
                                Key: {m.encryption_key_id} | {m.size_bytes} B | Rows: {m.row_count}
                              </div>
                            </div>
                            {canManage && (
                              <button
                                type="button"
                                disabled={busy}
                                onClick={() => void handleRunDrill(m.id)}
                                className="vf-btn-secondary h-7 px-3 text-xs"
                              >
                                Verify Restore
                              </button>
                            )}
                          </div>
                        ))
                      )}
                    </div>
                  </div>

                  <div className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-5">
                    <h2 className="text-base font-semibold text-white">
                      Immutable Restore Drills & Key Epochs
                    </h2>
                    <div className="mt-3 space-y-2 text-xs">
                      {overview.restore_drills.map((d) => (
                        <div
                          key={d.id}
                          className="rounded border border-white/[0.068] bg-[#0e0e11]/70 p-3"
                        >
                          <div className="flex justify-between font-medium text-white">
                            <span>{d.drill_mode}</span>
                            <span
                              className={
                                d.status === "passed" ? "text-zinc-200" : "text-rose-400"
                              }
                            >
                              {d.status.toUpperCase()} ({d.rto_observed_seconds}s)
                            </span>
                          </div>
                          <div className="mt-1 text-zinc-400">{d.findings_summary}</div>
                        </div>
                      ))}
                      {overview.keys.map((k) => (
                        <div
                          key={k.id}
                          className="rounded border border-white/[0.068] bg-[#0e0e11]/50 p-2.5 text-zinc-300"
                        >
                          Key <span className="font-semibold text-white">{k.key_id}</span> v
                          {k.version} ({k.purpose}) — <span className="uppercase">{k.status}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </section>
              </>
            )}
          </div>
        );
      }}
    </OrgShell>
  );
}
