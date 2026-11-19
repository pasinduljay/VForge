"use client";

import { useParams } from "next/navigation";
import { FormEvent, useCallback, useEffect, useState } from "react";
import OrgShell, { hasPermission } from "@/components/OrgShell";
import { Select } from "@/components/ui/Select";
import { apiFetch, formatUtc } from "@/lib/api";
import {
  MEMBERSHIP_STATUSES,
  ROLES,
  type Membership,
  type MembershipStatus,
  type PaginatedResponse,
  type Role,
} from "@/lib/types";

function MembersContent({
  orgId,
  canManage,
  currentRole,
  csrfToken,
}: {
  orgId: string;
  canManage: boolean;
  currentRole: Role | null;
  csrfToken: string | null;
}) {
  const [members, setMembers] = useState<Membership[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [oidcIssuer, setOidcIssuer] = useState("http://127.0.0.1:8080/realms/vforge");
  const [oidcSubject, setOidcSubject] = useState("");
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [role, setRole] = useState<Role>("developer");
  const [submitting, setSubmitting] = useState(false);

  const loadMembers = useCallback(async () => {
    try {
      const data = await apiFetch<PaginatedResponse<Membership>>(
        `/api/v1/organizations/${orgId}/memberships?limit=100`,
      );
      setMembers(data.items);
      setTotal(data.total);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load memberships");
    } finally {
      setLoading(false);
    }
  }, [orgId]);

  useEffect(() => {
    let active = true;
    void apiFetch<PaginatedResponse<Membership>>(
      `/api/v1/organizations/${orgId}/memberships?limit=100`,
    )
      .then((data) => {
        if (!active) return;
        setMembers(data.items);
        setTotal(data.total);
        setError(null);
        setLoading(false);
      })
      .catch((err) => {
        if (!active) return;
        setError(err instanceof Error ? err.message : "Failed to load memberships");
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [orgId]);

  const handleAddMember = async (e: FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    setNotice(null);
    try {
      await apiFetch<Membership>(`/api/v1/organizations/${orgId}/memberships`, {
        method: "POST",
        csrfToken,
        body: JSON.stringify({
          oidc_issuer: oidcIssuer.trim(),
          oidc_subject: oidcSubject.trim(),
          email: email.trim(),
          display_name: displayName.trim(),
          role,
          status: "active",
        }),
      });
      setOidcSubject("");
      setEmail("");
      setDisplayName("");
      setNotice("Member added with OIDC identity binding.");
      await loadMembers();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add member");
    } finally {
      setSubmitting(false);
    }
  };

  const handleUpdateMember = async (
    membershipId: string,
    patch: { role?: Role; status?: MembershipStatus },
  ) => {
    setError(null);
    setNotice(null);
    try {
      await apiFetch<Membership>(
        `/api/v1/organizations/${orgId}/memberships/${membershipId}`,
        {
          method: "PATCH",
          csrfToken,
          body: JSON.stringify(patch),
        },
      );
      setNotice("Membership updated.");
      await loadMembers();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update membership");
    }
  };

  const handleRemoveMember = async (membershipId: string) => {
    setError(null);
    setNotice(null);
    try {
      await apiFetch(`/api/v1/organizations/${orgId}/memberships/${membershipId}`, {
        method: "DELETE",
        csrfToken,
      });
      setNotice("Membership removed.");
      await loadMembers();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to remove membership");
    }
  };

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold text-white">Members & Role Management</h1>
        <p className="mt-1 text-sm text-zinc-400">
          Identities are bound to <code>(oidc_issuer, oidc_subject)</code>. Only an{" "}
          <code>owner</code> may assign or modify the <code>owner</code> role.
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
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-medium text-white">Organization Members ({total})</h2>
        </div>

        {loading ? (
          <p className="mt-4 text-sm text-zinc-400">Loading members...</p>
        ) : members.length === 0 ? (
          <p className="mt-4 text-sm text-zinc-400">No members found.</p>
        ) : (
          <div className="mt-4 overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-white/[0.068] text-xs uppercase text-zinc-400">
                <tr>
                  <th className="py-2 pr-4">User</th>
                  <th className="py-2 pr-4">OIDC Identity</th>
                  <th className="py-2 pr-4">Role</th>
                  <th className="py-2 pr-4">Status</th>
                  <th className="py-2 pr-4">Added</th>
                  {canManage ? <th className="py-2">Actions</th> : null}
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.06]">
                {members.map((m) => (
                  <tr key={m.id}>
                    <td className="py-3 pr-4">
                      <div className="font-medium text-white">{m.user_display_name}</div>
                      <div className="text-xs text-zinc-400">{m.user_email}</div>
                    </td>
                    <td className="py-3 pr-4 text-xs text-zinc-300">
                      <div className="truncate max-w-xs" title={m.oidc_issuer}>
                        {m.oidc_issuer}
                      </div>
                      <div className="text-zinc-400">sub: {m.oidc_subject}</div>
                    </td>
                    <td className="py-3 pr-4">
                      {canManage ? (
                        <div className="min-w-[140px]">
                          <Select
                            aria-label={`Role for ${m.user_email}`}
                            size="sm"
                            value={m.role}
                            onChange={(e) =>
                              void handleUpdateMember(m.id, { role: e.target.value as Role })
                            }
                          >
                            {ROLES.map((r) => (
                              <option
                                key={r}
                                value={r}
                                disabled={r === "owner" && currentRole !== "owner"}
                              >
                                {r}
                              </option>
                            ))}
                          </Select>
                        </div>
                      ) : (
                        <span className="rounded bg-[#1c1c20] px-2 py-0.5 text-xs">
                          {m.role}
                        </span>
                      )}
                    </td>
                    <td className="py-3 pr-4">
                      {canManage ? (
                        <div className="min-w-[115px]">
                          <Select
                            aria-label={`Status for ${m.user_email}`}
                            size="sm"
                            value={m.status}
                            onChange={(e) =>
                              void handleUpdateMember(m.id, {
                                status: e.target.value as MembershipStatus,
                              })
                            }
                          >
                            {MEMBERSHIP_STATUSES.map((s) => (
                              <option key={s} value={s}>
                                {s}
                              </option>
                            ))}
                          </Select>
                        </div>
                      ) : (
                        <span className="text-xs text-zinc-300">{m.status}</span>
                      )}
                    </td>
                    <td className="py-3 pr-4 text-xs text-zinc-400">
                      {formatUtc(m.created_at)}
                    </td>
                    {canManage ? (
                      <td className="py-3">
                        <button
                          type="button"
                          onClick={() => void handleRemoveMember(m.id)}
                          className="vf-btn-danger px-2.5 py-1 text-xs"
                        >
                          Remove
                        </button>
                      </td>
                    ) : null}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {canManage ? (
        <section className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-6">
          <h2 className="text-lg font-medium text-white">Add Member</h2>
          <form onSubmit={handleAddMember} className="mt-4 grid gap-4 sm:grid-cols-2">
            <div>
              <label className="block text-xs font-medium text-zinc-300">
                OIDC Issuer URL
              </label>
              <input
                type="url"
                required
                value={oidcIssuer}
                onChange={(e) => setOidcIssuer(e.target.value)}
                className="mt-1 vf-input"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-zinc-300">
                OIDC Subject (`sub`)
              </label>
              <input
                type="text"
                required
                value={oidcSubject}
                onChange={(e) => setOidcSubject(e.target.value)}
                placeholder="f47ac10b-58cc-4372-a567-0e02b2c3d479"
                className="mt-1 vf-input"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-zinc-300">Email</label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@example.com"
                className="mt-1 vf-input"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-zinc-300">
                Display Name
              </label>
              <input
                type="text"
                required
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                placeholder="Security Analyst"
                className="mt-1 vf-input"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-zinc-300">Role</label>
              <Select
                value={role}
                onChange={(e) => setRole(e.target.value as Role)}
                className="mt-1"
              >
                {ROLES.map((r) => (
                  <option
                    key={r}
                    value={r}
                    disabled={r === "owner" && currentRole !== "owner"}
                  >
                    {r}
                  </option>
                ))}
              </Select>
            </div>
            <div className="sm:col-span-2">
              <button
                type="submit"
                disabled={submitting}
                className="vf-btn-primary h-8 px-4 text-xs"
              >
                {submitting ? "Adding..." : "Add Member"}
              </button>
            </div>
          </form>
        </section>
      ) : null}
    </div>
  );
}

export default function MembersPage() {
  const params = useParams<{ orgId: string }>();
  const orgId = params.orgId;
  return (
    <OrgShell orgId={orgId}>
      {({ auth, membership }) => (
        <MembersContent
          orgId={orgId}
          canManage={hasPermission(membership, "membership:manage")}
          currentRole={membership?.role ?? null}
          csrfToken={auth.csrf_token}
        />
      )}
    </OrgShell>
  );
}
