"use client";

import { useParams } from "next/navigation";
import { FormEvent, useCallback, useEffect, useState } from "react";
import OrgShell from "@/components/OrgShell";
import { apiFetch, formatUtc } from "@/lib/api";
import type { AuditEvent, PaginatedResponse } from "@/lib/types";

function AuditContent({ orgId }: { orgId: string }) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [actionFilter, setActionFilter] = useState("");
  const [submittedAction, setSubmittedAction] = useState("");
  const [offset, setOffset] = useState(0);
  const limit = 25;
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchAudit = useCallback(async () => {
    const params = new URLSearchParams({
      limit: String(limit),
      offset: String(offset),
    });
    if (submittedAction) {
      params.set("action", submittedAction);
    }
    return apiFetch<PaginatedResponse<AuditEvent>>(
      `/api/v1/organizations/${orgId}/audit-events?${params.toString()}`,
    );
  }, [orgId, offset, submittedAction]);

  useEffect(() => {
    let active = true;
    void fetchAudit()
      .then((res) => {
        if (!active) return;
        setEvents(res.items);
        setTotal(res.total);
        setError(null);
        setLoading(false);
      })
      .catch((err) => {
        if (!active) return;
        setError(err instanceof Error ? err.message : "Failed to load audit events");
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [fetchAudit]);

  const handleFilter = (e: FormEvent) => {
    e.preventDefault();
    setOffset(0);
    setSubmittedAction(actionFilter.trim());
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-white">
            Immutable Security Audit Log ({total})
          </h1>
          <p className="mt-1 text-sm text-zinc-400">
            Append-only organization events enforced by PostgreSQL triggers and RBAC
            (`audit:read`).
          </p>
        </div>

        <form onSubmit={handleFilter} className="flex gap-2">
          <input
            type="text"
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            placeholder="Filter action (e.g. authorization.approved)"
            className="w-64 rounded-md border border-white/[0.1] bg-[#111114] px-3 py-1.5 text-sm text-white"
          />
          <button
            type="submit"
            className="vf-btn-secondary h-8 px-4 text-xs"
          >
            Filter
          </button>
        </form>
      </div>

      {error ? (
        <div className="rounded-md border border-white/[0.08] bg-[#131317] p-4 text-sm text-zinc-200">
          {error}
        </div>
      ) : null}

      <section className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-6">
        {loading ? (
          <p className="text-sm text-zinc-400">Loading audit events...</p>
        ) : events.length === 0 ? (
          <p className="text-sm text-zinc-400">No audit events matched.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-white/[0.068] uppercase text-zinc-400">
                <tr>
                  <th className="py-2 pr-4">Timestamp</th>
                  <th className="py-2 pr-4">Action</th>
                  <th className="py-2 pr-4">Resource</th>
                  <th className="py-2 pr-4">Outcome</th>
                  <th className="py-2 pr-4">Correlation ID</th>
                  <th className="py-2">Metadata</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.06]">
                {events.map((ev) => (
                  <tr key={ev.id}>
                    <td className="py-3 pr-4 whitespace-nowrap text-zinc-400">
                      {formatUtc(ev.created_at)}
                    </td>
                    <td className="py-3 pr-4 font-mono text-zinc-200">{ev.action}</td>
                    <td className="py-3 pr-4 text-zinc-300">
                      {ev.resource_type || "—"}
                      {ev.resource_id ? ` (${ev.resource_id.slice(0, 8)})` : ""}
                    </td>
                    <td className="py-3 pr-4 text-zinc-200">{ev.outcome}</td>
                    <td className="py-3 pr-4 font-mono text-zinc-400">
                      {ev.correlation_id ? ev.correlation_id.slice(0, 12) : "—"}
                    </td>
                    <td className="py-3 font-mono text-zinc-300">
                      {JSON.stringify(ev.metadata)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="mt-4 flex items-center justify-between text-xs text-zinc-400">
          <span>
            Showing {events.length} of {total} events (offset {offset})
          </span>
          <div className="flex gap-2">
            <button
              type="button"
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - limit))}
              className="vf-btn-secondary h-7 px-3 text-xs"
            >
              Previous
            </button>
            <button
              type="button"
              disabled={offset + limit >= total}
              onClick={() => setOffset(offset + limit)}
              className="vf-btn-secondary h-7 px-3 text-xs"
            >
              Next
            </button>
          </div>
        </div>
      </section>
    </div>
  );
}

export default function AuditPage() {
  const params = useParams<{ orgId: string }>();
  return (
    <OrgShell orgId={params.orgId}>
      {() => <AuditContent orgId={params.orgId} />}
    </OrgShell>
  );
}
