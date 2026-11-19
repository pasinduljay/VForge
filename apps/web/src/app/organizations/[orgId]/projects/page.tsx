"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { FormEvent, useCallback, useEffect, useState } from "react";
import OrgShell, { hasPermission } from "@/components/OrgShell";
import { Badge } from "@/components/ui/Badge";
import { PageHeader } from "@/components/ui/PageHeader";
import { Select } from "@/components/ui/Select";
import { apiFetch, formatUtc } from "@/lib/api";
import {
  ENVIRONMENT_TYPES,
  PROJECT_CRITICALITIES,
  type Environment,
  type EnvironmentType,
  type PaginatedResponse,
  type Project,
  type ProjectCriticality,
  type ProjectStatus,
} from "@/lib/types";

function slugifyName(input: string): string {
  return input
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
}

function ProjectsContent({
  orgId,
  canCreate,
  canUpdate,
  canDelete,
  csrfToken,
}: {
  orgId: string;
  canCreate: boolean;
  canUpdate: boolean;
  canDelete: boolean;
  csrfToken: string | null;
}) {
  const [projects, setProjects] = useState<Project[]>([]);
  const [total, setTotal] = useState(0);
  const [statusFilter, setStatusFilter] = useState<"" | ProjectStatus>("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [showNextAssetLink, setShowNextAssetLink] = useState(false);

  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [slugEdited, setSlugEdited] = useState(false);
  const [description, setDescription] = useState("");
  const [criticality, setCriticality] = useState<ProjectCriticality>("medium");
  const [createInitialEnv, setCreateInitialEnv] = useState(true);
  const [initialEnvName, setInitialEnvName] = useState("Staging");
  const [initialEnvType, setInitialEnvType] = useState<EnvironmentType>("staging");
  const [submitting, setSubmitting] = useState(false);
  const [updatingId, setUpdatingId] = useState<string | null>(null);
  const [archiveCandidateId, setArchiveCandidateId] = useState<string | null>(null);

  const fetchProjects = useCallback(async () => {
    const qs = statusFilter ? `?status=${encodeURIComponent(statusFilter)}` : "";
    return apiFetch<PaginatedResponse<Project>>(
      `/api/v1/organizations/${orgId}/projects${qs}`,
    );
  }, [orgId, statusFilter]);

  const loadProjects = useCallback(async () => {
    try {
      const res = await fetchProjects();
      setProjects(res.items);
      setTotal(res.total);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load projects");
    } finally {
      setLoading(false);
    }
  }, [fetchProjects]);

  useEffect(() => {
    let active = true;
    void fetchProjects()
      .then((res) => {
        if (!active) return;
        setProjects(res.items);
        setTotal(res.total);
        setError(null);
        setLoading(false);
      })
      .catch((err) => {
        if (!active) return;
        setError(err instanceof Error ? err.message : "Failed to load projects");
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [fetchProjects]);

  const handleCreate = async (e: FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    setNotice(null);
    setShowNextAssetLink(false);
    try {
      const created = await apiFetch<Project>(
        `/api/v1/organizations/${orgId}/projects`,
        {
          method: "POST",
          csrfToken,
          body: JSON.stringify({
            name: name.trim(),
            slug: slug.trim(),
            description: description.trim() || null,
            criticality,
          }),
        },
      );

      let envMsg = "";
      if (createInitialEnv && initialEnvName.trim()) {
        try {
          const env = await apiFetch<Environment>(
            `/api/v1/organizations/${orgId}/projects/${created.id}/environments`,
            {
              method: "POST",
              csrfToken,
              body: JSON.stringify({
                name: initialEnvName.trim(),
                environment_type: initialEnvType,
              }),
            },
          );
          envMsg = ` Initial environment "${env.name}" (${env.environment_type}) created — ready for Step 2.`;
          setShowNextAssetLink(true);
        } catch (envErr) {
          envMsg = ` Project created, but initial environment failed: ${
            envErr instanceof Error ? envErr.message : "unknown error"
          }. Add an environment in project details.`;
        }
      }

      setName("");
      setSlug("");
      setSlugEdited(false);
      setDescription("");
      setNotice(`Project "${created.name}" created.${envMsg}`);
      await loadProjects();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create project");
    } finally {
      setSubmitting(false);
    }
  };

  const handleToggleArchive = async (project: Project) => {
    setError(null);
    setNotice(null);
    setArchiveCandidateId(null);
    setUpdatingId(project.id);
    const nextStatus: ProjectStatus =
      project.status === "archived" ? "active" : "archived";
    try {
      await apiFetch(`/api/v1/organizations/${orgId}/projects/${project.id}`, {
        method: "PATCH",
        csrfToken,
        body: JSON.stringify({ status: nextStatus }),
      });
      setNotice(
        nextStatus === "archived"
          ? `Project "${project.name}" archived.`
          : `Project "${project.name}" restored to active.`,
      );
      await loadProjects();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to update project status",
      );
    } finally {
      setUpdatingId(null);
    }
  };

  const handleDelete = async (projectId: string) => {
    setError(null);
    setNotice(null);
    setArchiveCandidateId(null);
    try {
      await apiFetch(`/api/v1/organizations/${orgId}/projects/${projectId}`, {
        method: "DELETE",
        csrfToken,
      });
      setNotice("Project deleted.");
      await loadProjects();
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to delete project";
      setError(msg);
      if (msg.toLowerCase().includes("archive")) {
        setArchiveCandidateId(projectId);
      }
    }
  };

  const archiveCandidate = archiveCandidateId
    ? projects.find((item) => item.id === archiveCandidateId) ?? null
    : null;

  return (
    <div className="space-y-8">
      <PageHeader
        eyebrow="Step 1 · Projects"
        title={`Projects (${total})`}
        description="Group your apps, microservices, or environments into Projects — like AWS accounts or folders for each workload."
        actions={
          <div className="w-full sm:w-44">
            <Select
              aria-label="Filter projects by status"
              size="sm"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as "" | ProjectStatus)}
            >
              <option value="">All statuses</option>
              <option value="active">active</option>
              <option value="archived">archived</option>
            </Select>
          </div>
        }
      />

      {error ? (
        <div className="vf-surface flex flex-wrap items-center justify-between gap-3 rounded-xl px-4 py-3 text-[13px] text-zinc-200">
          <p className="min-w-0 flex-1 text-rose-300">{error}</p>
          {canUpdate && archiveCandidate && archiveCandidate.status !== "archived" ? (
            <button
              type="button"
              disabled={updatingId === archiveCandidate.id}
              onClick={() => void handleToggleArchive(archiveCandidate)}
              className="vf-btn-warning px-3 py-1.5 text-xs"
            >
              {updatingId === archiveCandidate.id
                ? "Archiving..."
                : "Archive Project Instead"}
            </button>
          ) : null}
        </div>
      ) : null}
      {notice ? (
        <div className="vf-surface rounded-xl px-4 py-3 text-[13px] text-emerald-300">
          {notice}
        </div>
      ) : null}

      <section className="space-y-3">
        {loading ? (
          <p className="text-sm text-zinc-400">Loading projects...</p>
        ) : projects.length === 0 ? (
          <div className="vf-surface rounded-2xl p-6 text-sm text-zinc-400">
            No projects match the current filter.
          </div>
        ) : (
          <div className="grid gap-4 sm:grid-cols-2">
            {projects.map((p) => (
              <div
                key={p.id}
                className="vf-surface flex flex-col justify-between rounded-2xl p-5"
              >
                <div>
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <Link
                      href={`/organizations/${orgId}/projects/${p.id}`}
                      className="text-base font-semibold tracking-tight text-white hover:underline"
                    >
                      {p.name}
                    </Link>
                    <div className="flex items-center gap-1.5">
                      <Badge
                        tone={
                          p.criticality === "critical" || p.criticality === "high"
                            ? "warning"
                            : "neutral"
                        }
                      >
                        {p.criticality}
                      </Badge>
                      <Badge
                        dot
                        tone={p.status === "archived" ? "neutral" : "success"}
                      >
                        {p.status}
                      </Badge>
                    </div>
                  </div>
                  <p className="mt-1.5 text-xs text-zinc-400">
                    Slug: <code className="font-mono text-zinc-300">{p.slug}</code> · Created {formatUtc(p.created_at)}
                  </p>
                  {p.description ? (
                    <p className="mt-2.5 text-[13px] leading-relaxed text-zinc-300">
                      {p.description}
                    </p>
                  ) : null}
                </div>
                <div className="mt-5 flex flex-wrap items-center justify-between gap-2 pt-3 border-t border-white/[0.06]">
                  <Link
                    href={`/organizations/${orgId}/projects/${p.id}`}
                    className="vf-btn-secondary px-3 py-1.5 text-xs"
                  >
                    Details & Environments
                  </Link>
                  <div className="flex items-center gap-2">
                    {canUpdate ? (
                      <button
                        type="button"
                        disabled={updatingId === p.id}
                        onClick={() => void handleToggleArchive(p)}
                        className={
                          p.status === "archived"
                            ? "vf-btn-secondary px-2.5 py-1.5 text-xs"
                            : "vf-btn-warning px-2.5 py-1.5 text-xs"
                        }
                      >
                        {updatingId === p.id
                          ? "Updating..."
                          : p.status === "archived"
                            ? "Restore"
                            : "Archive"}
                      </button>
                    ) : null}
                    {canDelete ? (
                      <button
                        type="button"
                        onClick={() => void handleDelete(p.id)}
                        className="vf-btn-danger px-2.5 py-1.5 text-xs"
                      >
                        Delete
                      </button>
                    ) : null}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {canCreate ? (
        <section className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-6">
          <h2 className="text-lg font-medium text-white">Create Project</h2>
          <form onSubmit={handleCreate} className="mt-4 grid gap-4 sm:grid-cols-2">
            <div>
              <label className="block text-xs font-medium text-zinc-300">Name</label>
              <input
                type="text"
                required
                minLength={2}
                value={name}
                onChange={(e) => {
                  const val = e.target.value;
                  setName(val);
                  if (!slugEdited) {
                    setSlug(slugifyName(val));
                  }
                }}
                placeholder="Customer Portal"
                className="vf-input mt-1"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-zinc-300">Slug</label>
              <input
                type="text"
                required
                minLength={2}
                value={slug}
                onChange={(e) => {
                  setSlugEdited(true);
                  setSlug(e.target.value);
                }}
                placeholder="customer-portal"
                className="vf-input mt-1"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-zinc-300">
                Criticality
              </label>
              <Select
                value={criticality}
                onChange={(e) => setCriticality(e.target.value as ProjectCriticality)}
                className="mt-1"
              >
                {PROJECT_CRITICALITIES.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </Select>
            </div>
            <div>
              <label className="block text-xs font-medium text-zinc-300">
                Description
              </label>
              <input
                type="text"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Scope summary or owning team"
                className="vf-input mt-1"
              />
            </div>
            <div className="sm:col-span-2 rounded-xl border border-white/[0.068] bg-[#101013]/80 p-4 space-y-3">
              <label className="flex items-center gap-2 text-xs font-medium text-zinc-200">
                <input
                  type="checkbox"
                  checked={createInitialEnv}
                  onChange={(e) => setCreateInitialEnv(e.target.checked)}
                  className="rounded border-white/[0.15] bg-[#0e0e11]"
                />
                Automatically create an initial environment (required before Step 2: Register Target Assets)
              </label>
              {createInitialEnv && (
                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <label className="block text-xs text-zinc-400">
                      Initial Environment Name
                    </label>
                    <input
                      type="text"
                      required={createInitialEnv}
                      minLength={2}
                      value={initialEnvName}
                      onChange={(e) => setInitialEnvName(e.target.value)}
                      placeholder="Staging"
                      className="vf-input mt-1"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-zinc-400">
                      Environment Type
                    </label>
                    <Select
                      value={initialEnvType}
                      onChange={(e) =>
                        setInitialEnvType(e.target.value as EnvironmentType)
                      }
                      className="mt-1"
                    >
                      {ENVIRONMENT_TYPES.map((envT) => (
                        <option key={envT} value={envT}>
                          {envT}
                        </option>
                      ))}
                    </Select>
                  </div>
                </div>
              )}
            </div>
            {showNextAssetLink && (
              <div className="sm:col-span-2 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-white/[0.08] bg-[#19191f] px-4 py-2.5 text-xs text-zinc-200">
                <span>Project and environment are ready. Next: register a URL, domain, IP, or container image.</span>
                <Link
                  href={`/organizations/${orgId}/assets`}
                  className="vf-btn-primary rounded-full px-3 py-1 text-xs"
                >
                  Step 2: Register Target Asset →
                </Link>
              </div>
            )}
            <div className="sm:col-span-2">
              <button
                type="submit"
                disabled={submitting}
                className="vf-btn-primary h-8 px-4 text-xs"
              >
                {submitting ? "Creating..." : "Create Project"}
              </button>
            </div>
          </form>
        </section>
      ) : null}
    </div>
  );
}

export default function ProjectsPage() {
  const params = useParams<{ orgId: string }>();
  const orgId = params.orgId;
  return (
    <OrgShell orgId={orgId}>
      {({ auth, membership }) => (
        <ProjectsContent
          orgId={orgId}
          canCreate={hasPermission(membership, "project:create")}
          canUpdate={hasPermission(membership, "project:update")}
          canDelete={hasPermission(membership, "project:delete")}
          csrfToken={auth.csrf_token}
        />
      )}
    </OrgShell>
  );
}
