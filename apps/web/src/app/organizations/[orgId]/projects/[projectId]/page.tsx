"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { FormEvent, useCallback, useEffect, useState } from "react";
import OrgShell, { hasPermission } from "@/components/OrgShell";
import { Select } from "@/components/ui/Select";
import { apiFetch, formatUtc } from "@/lib/api";
import {
  AUTH_PROFILE_TYPES,
  ENVIRONMENT_STATUSES,
  ENVIRONMENT_TYPES,
  PROJECT_CRITICALITIES,
  PROJECT_STATUSES,
  type AuthProfile,
  type AuthProfileType,
  type Environment,
  type EnvironmentStatus,
  type EnvironmentType,
  type PaginatedResponse,
  type Project,
  type ProjectCriticality,
  type ProjectStatus,
} from "@/lib/types";

function ProjectDetailContent({
  orgId,
  projectId,
  canUpdateProject,
  canManageEnv,
  canReadAuthProfiles,
  canManageAuthProfiles,
  csrfToken,
}: {
  orgId: string;
  projectId: string;
  canUpdateProject: boolean;
  canManageEnv: boolean;
  canReadAuthProfiles: boolean;
  canManageAuthProfiles: boolean;
  csrfToken: string | null;
}) {
  const [project, setProject] = useState<Project | null>(null);
  const [environments, setEnvironments] = useState<Environment[]>([]);
  const [authProfilesByEnv, setAuthProfilesByEnv] = useState<
    Record<string, AuthProfile[]>
  >({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [projName, setProjName] = useState("");
  const [projDesc, setProjDesc] = useState("");
  const [projCrit, setProjCrit] = useState<ProjectCriticality>("medium");
  const [projStatus, setProjStatus] = useState<ProjectStatus>("active");

  const [envName, setEnvName] = useState("");
  const [envType, setEnvType] = useState<EnvironmentType>("staging");

  const [selectedEnvForAuth, setSelectedEnvForAuth] = useState("");
  const [apName, setApName] = useState("");
  const [apType, setApType] = useState<AuthProfileType>("oauth2_client_credentials");
  const [apSecretRef, setApSecretRef] = useState("");

  const fetchDetail = useCallback(async () => {
    const [proj, envRes] = await Promise.all([
      apiFetch<Project>(`/api/v1/organizations/${orgId}/projects/${projectId}`),
      apiFetch<PaginatedResponse<Environment>>(
        `/api/v1/organizations/${orgId}/projects/${projectId}/environments?limit=100`,
      ),
    ]);
    let profilesMap: Record<string, AuthProfile[]> = {};
    if (canReadAuthProfiles && envRes.items.length > 0) {
      const entries = await Promise.all(
        envRes.items.map(async (env) => {
          const ap = await apiFetch<PaginatedResponse<AuthProfile>>(
            `/api/v1/organizations/${orgId}/environments/${env.id}/auth-profiles?limit=50`,
          );
          return [env.id, ap.items] as const;
        }),
      );
      profilesMap = Object.fromEntries(entries);
    }
    return { proj, envs: envRes.items, profilesMap };
  }, [orgId, projectId, canReadAuthProfiles]);

  const applyDetail = useCallback(
    (data: {
      proj: Project;
      envs: Environment[];
      profilesMap: Record<string, AuthProfile[]>;
    }) => {
      setProject(data.proj);
      setProjName(data.proj.name);
      setProjDesc(data.proj.description || "");
      setProjCrit(data.proj.criticality);
      setProjStatus(data.proj.status);
      setEnvironments(data.envs);
      setAuthProfilesByEnv(data.profilesMap);
      if (data.envs.length > 0) {
        setSelectedEnvForAuth((prev) => prev || data.envs[0].id);
      }
      setError(null);
      setLoading(false);
    },
    [],
  );

  const load = useCallback(async () => {
    try {
      applyDetail(await fetchDetail());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load project details");
      setLoading(false);
    }
  }, [applyDetail, fetchDetail]);

  useEffect(() => {
    let active = true;
    void fetchDetail()
      .then((data) => {
        if (!active) return;
        applyDetail(data);
      })
      .catch((err) => {
        if (!active) return;
        setError(err instanceof Error ? err.message : "Failed to load project details");
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [applyDetail, fetchDetail]);

  const handleUpdateProject = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);
    try {
      await apiFetch<Project>(`/api/v1/organizations/${orgId}/projects/${projectId}`, {
        method: "PATCH",
        csrfToken,
        body: JSON.stringify({
          name: projName.trim(),
          description: projDesc.trim() || null,
          criticality: projCrit,
          status: projStatus,
        }),
      });
      setNotice("Project details updated.");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update project");
    }
  };

  const handleCreateEnvironment = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);
    try {
      const env = await apiFetch<Environment>(
        `/api/v1/organizations/${orgId}/projects/${projectId}/environments`,
        {
          method: "POST",
          csrfToken,
          body: JSON.stringify({
            name: envName.trim(),
            environment_type: envType,
          }),
        },
      );
      setEnvName("");
      setSelectedEnvForAuth(env.id);
      setNotice(`Environment '${env.name}' created.`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create environment");
    }
  };

  const handleEnvStatusChange = async (envId: string, status: EnvironmentStatus) => {
    setError(null);
    setNotice(null);
    try {
      await apiFetch<Environment>(
        `/api/v1/organizations/${orgId}/environments/${envId}`,
        {
          method: "PATCH",
          csrfToken,
          body: JSON.stringify({ status }),
        },
      );
      setNotice("Environment status updated.");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update environment");
    }
  };

  const handleCreateAuthProfile = async (e: FormEvent) => {
    e.preventDefault();
    if (!selectedEnvForAuth) {
      return;
    }
    setError(null);
    setNotice(null);
    try {
      await apiFetch<AuthProfile>(
        `/api/v1/organizations/${orgId}/environments/${selectedEnvForAuth}/auth-profiles`,
        {
          method: "POST",
          csrfToken,
          body: JSON.stringify({
            name: apName.trim(),
            auth_type: apType,
            secret_manager_ref: apSecretRef.trim(),
          }),
        },
      );
      setApName("");
      setApSecretRef("");
      setNotice("Authentication profile reference registered.");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to register auth profile");
    }
  };

  if (loading) {
    return <p className="text-sm text-zinc-400">Loading project details...</p>;
  }

  return (
    <div className="space-y-8">
      <div>
        <Link
          href={`/organizations/${orgId}/projects`}
          className="text-xs text-zinc-200 hover:underline"
        >
          ← Back to Projects
        </Link>
        <h1 className="mt-2 text-2xl font-semibold text-white">
          {project?.name || "Project"}
        </h1>
        {project ? (
          <p className="mt-1 text-xs text-zinc-400">
            Slug: <code>{project.slug}</code> · Updated {formatUtc(project.updated_at)}
          </p>
        ) : null}
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

      {project && canUpdateProject ? (
        <section className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-6">
          <h2 className="text-lg font-medium text-white">Project Details</h2>
          <form onSubmit={handleUpdateProject} className="mt-4 grid gap-4 sm:grid-cols-2">
            <div>
              <label className="block text-xs text-zinc-300">Name</label>
              <input
                type="text"
                required
                minLength={2}
                value={projName}
                onChange={(e) => setProjName(e.target.value)}
                className="mt-1 vf-input"
              />
            </div>
            <div>
              <label className="block text-xs text-zinc-300">Criticality</label>
              <Select
                value={projCrit}
                onChange={(e) => setProjCrit(e.target.value as ProjectCriticality)}
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
              <label className="block text-xs text-zinc-300">Status</label>
              <Select
                value={projStatus}
                onChange={(e) => setProjStatus(e.target.value as ProjectStatus)}
                className="mt-1"
              >
                {PROJECT_STATUSES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </Select>
            </div>
            <div>
              <label className="block text-xs text-zinc-300">Description</label>
              <input
                type="text"
                value={projDesc}
                onChange={(e) => setProjDesc(e.target.value)}
                className="mt-1 vf-input"
              />
            </div>
            <div className="sm:col-span-2">
              <button
                type="submit"
                className="vf-btn-primary h-8 px-4 text-xs"
              >
                Save Project
              </button>
            </div>
          </form>
        </section>
      ) : null}

      <section className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-6">
        <h2 className="text-lg font-medium text-white">
          Environments ({environments.length})
        </h2>
        {environments.length === 0 ? (
          <p className="mt-3 text-sm text-zinc-400">
            No environments registered under this project yet.
          </p>
        ) : (
          <div className="mt-4 space-y-4">
            {environments.map((env) => {
              const profiles = authProfilesByEnv[env.id] || [];
              return (
                <div
                  key={env.id}
                  className="rounded-lg border border-white/[0.068] bg-[#0e0e11] p-4"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <h3 className="text-base font-medium text-white">{env.name}</h3>
                      <p className="text-xs text-zinc-400">
                        Type: <code>{env.environment_type}</code> · ID:{" "}
                        <code>{env.id}</code>
                      </p>
                    </div>
                    {canManageEnv ? (
                      <div className="w-36">
                        <Select
                          aria-label={`Status for ${env.name}`}
                          size="sm"
                          value={env.status}
                          onChange={(e) =>
                            void handleEnvStatusChange(
                              env.id,
                              e.target.value as EnvironmentStatus,
                            )
                          }
                        >
                          {ENVIRONMENT_STATUSES.map((s) => (
                            <option key={s} value={s}>
                              {s}
                            </option>
                          ))}
                        </Select>
                      </div>
                    ) : (
                      <span className="rounded bg-[#1c1c20] px-2 py-0.5 text-xs">
                        {env.status}
                      </span>
                    )}
                  </div>

                  {canReadAuthProfiles ? (
                    <div className="mt-3 border-t border-white/[0.08] pt-3">
                      <p className="text-xs font-medium text-zinc-300">
                        Authentication Profile References ({profiles.length})
                      </p>
                      {profiles.length === 0 ? (
                        <p className="mt-1 text-xs text-zinc-500">
                          None configured for this environment.
                        </p>
                      ) : (
                        <ul className="mt-2 space-y-1 text-xs text-zinc-300">
                          {profiles.map((ap) => (
                            <li key={ap.id} className="flex flex-wrap gap-2">
                              <span className="font-medium text-white">{ap.name}</span>
                              <span className="text-zinc-400">({ap.auth_type})</span>
                              <code className="text-zinc-200">
                                {ap.secret_manager_ref}
                              </code>
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  ) : null}
                </div>
              );
            })}
          </div>
        )}

        {canManageEnv ? (
          <form onSubmit={handleCreateEnvironment} className="mt-6 grid gap-3 sm:grid-cols-3">
            <input
              type="text"
              required
              value={envName}
              onChange={(e) => setEnvName(e.target.value)}
              placeholder="Environment name (e.g. staging-eu)"
              className="rounded-md border border-white/[0.1] bg-[#0e0e11] px-3 py-2 text-sm text-white"
            />
            <Select
              value={envType}
              onChange={(e) => setEnvType(e.target.value as EnvironmentType)}
            >
              {ENVIRONMENT_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </Select>
            <button
              type="submit"
              className="vf-btn-primary h-8 px-4 text-xs"
            >
              Add Environment
            </button>
          </form>
        ) : null}
      </section>

      {canManageAuthProfiles && environments.length > 0 ? (
        <section className="rounded-2xl border border-white/[0.068] bg-[#131316] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] p-6">
          <h2 className="text-lg font-medium text-white">
            Register Authentication Profile Reference
          </h2>
          <p className="mt-1 text-xs text-zinc-400">
            Store only secret-manager references (e.g. <code>vault://...</code> or{" "}
            <code>secrets://...</code>). Plaintext secrets are rejected.
          </p>
          <form onSubmit={handleCreateAuthProfile} className="mt-4 grid gap-4 sm:grid-cols-2">
            <div>
              <label className="block text-xs text-zinc-300">Environment</label>
              <Select
                value={selectedEnvForAuth}
                onChange={(e) => setSelectedEnvForAuth(e.target.value)}
                className="mt-1"
              >
                {environments.map((env) => (
                  <option key={env.id} value={env.id}>
                    {env.name} ({env.environment_type})
                  </option>
                ))}
              </Select>
            </div>
            <div>
              <label className="block text-xs text-zinc-300">Profile Name</label>
              <input
                type="text"
                required
                minLength={2}
                value={apName}
                onChange={(e) => setApName(e.target.value)}
                placeholder="staging-oauth-client"
                className="mt-1 vf-input"
              />
            </div>
            <div>
              <label className="block text-xs text-zinc-300">Auth Type</label>
              <Select
                value={apType}
                onChange={(e) => setApType(e.target.value as AuthProfileType)}
                className="mt-1"
              >
                {AUTH_PROFILE_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </Select>
            </div>
            <div>
              <label className="block text-xs text-zinc-300">
                Secret Manager URI Reference
              </label>
              <input
                type="text"
                required
                minLength={6}
                value={apSecretRef}
                onChange={(e) => setApSecretRef(e.target.value)}
                placeholder="vault://vforge/staging/api-client"
                className="mt-1 vf-input"
              />
            </div>
            <div className="sm:col-span-2">
              <button
                type="submit"
                className="vf-btn-primary h-8 px-4 text-xs"
              >
                Register Secret Reference
              </button>
            </div>
          </form>
        </section>
      ) : null}
    </div>
  );
}

export default function ProjectDetailPage() {
  const params = useParams<{ orgId: string; projectId: string }>();
  return (
    <OrgShell orgId={params.orgId}>
      {({ auth, membership }) => (
        <ProjectDetailContent
          orgId={params.orgId}
          projectId={params.projectId}
          canUpdateProject={hasPermission(membership, "project:update")}
          canManageEnv={hasPermission(membership, "environment:manage")}
          canReadAuthProfiles={hasPermission(membership, "auth_profile:read")}
          canManageAuthProfiles={hasPermission(membership, "auth_profile:manage")}
          csrfToken={auth.csrf_token}
        />
      )}
    </OrgShell>
  );
}
