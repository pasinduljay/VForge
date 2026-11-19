"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Activity,
  Bell,
  Bot,
  Bug,
  Building2,
  Check,
  ChevronDown,
  Code2,
  Cpu,
  FileArchive,
  FileText,
  FolderKanban,
  Globe,
  GraduationCap,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Menu,
  PackageSearch,
  PanelLeftClose,
  PanelLeftOpen,
  PlayCircle,
  Plug,
  Plus,
  Radar,
  RefreshCw,
  ScrollText,
  Server,
  Settings,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Swords,
  Users,
  X,
  type LucideIcon,
} from "lucide-react";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { ApiError, apiFetch, signOutAndRedirect } from "@/lib/api";
import { cn } from "@/lib/cn";
import { NAV_GROUPS, WORKSPACE_NAV_ITEMS } from "@/lib/navigation";
import type {
  AuthMe,
  FindingItem,
  OrganizationMembershipSummary,
  OrgThreatIntelSummary,
  PaginatedResponse,
  Project,
  RunnerItem,
  ScanRunSummary,
} from "@/lib/types";
import { Badge } from "@/components/ui/Badge";
import { Select } from "@/components/ui/Select";
import { ThemeToggle, useTheme } from "@/components/ThemeProvider";

const ICON_MAP: Record<string, LucideIcon> = {
  LayoutDashboard,
  FolderKanban,
  Server,
  ShieldCheck,
  Radar,
  SlidersHorizontal,
  PlayCircle,
  Bug,
  FileArchive,
  FileText,
  Globe,
  PackageSearch,
  Cpu,
  RefreshCw,
  Code2,
  Bot,
  GraduationCap,
  Swords,
  Users,
  ScrollText,
  KeyRound,
  Plug,
  Activity,
  Settings,
};

interface OrgWorkspaceContextValue {
  orgId: string;
  projects: Project[];
  selectedProjectId: string;
  setSelectedProjectId: (id: string) => void;
}

const OrgWorkspaceContext = createContext<OrgWorkspaceContextValue | null>(null);

export function useOrgWorkspaceContext() {
  return useContext(OrgWorkspaceContext);
}

interface PostureSignal {
  id: string;
  title: string;
  detail: string;
  href: string;
  tone: "warning" | "danger" | "info";
}

interface OrgShellProps {
  orgId: string;
  children: (ctx: {
    auth: AuthMe;
    membership: OrganizationMembershipSummary | null;
    reloadAuth: () => Promise<void>;
  }) => React.ReactNode;
}

export function hasPermission(
  membership: OrganizationMembershipSummary | null,
  permission: string,
): boolean {
  return membership ? membership.permissions.includes(permission) : false;
}

function resolveBreadcrumbs(orgId: string, pathname: string, orgName: string) {
  const basePath = `/organizations/${orgId}`;
  const tail = pathname.startsWith(basePath)
    ? pathname.slice(basePath.length).replace(/^\/+/, "")
    : "";
  const parts = tail ? tail.split("/") : [];
  const crumbs: Array<{ label: string; href?: string }> = [
    { label: "Organizations", href: "/organizations?manage=1" },
    { label: orgName, href: basePath },
  ];

  if (parts.length === 0) {
    crumbs.push({ label: "Dashboard" });
    return crumbs;
  }

  const primary = parts[0];
  const navMatch = WORKSPACE_NAV_ITEMS.find((item) => item.segment === primary);
  if (navMatch) {
    crumbs.push({
      label: navMatch.group,
    });
    if (parts.length > 1) {
      crumbs.push({
        label: navMatch.label,
        href: `${basePath}/${navMatch.segment}`,
      });
      crumbs.push({
        label: `Detail (${parts[1].slice(0, 8)})`,
      });
    } else {
      crumbs.push({ label: navMatch.label });
    }
  } else {
    crumbs.push({ label: primary });
  }
  return crumbs;
}

export default function OrgShell({ orgId, children }: OrgShellProps) {
  const pathname = usePathname();
  const router = useRouter();
  const { theme, resolvedTheme } = useTheme();
  const [auth, setAuth] = useState<AuthMe | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [signingOut, setSigningOut] = useState(false);
  const [rotatingSession, setRotatingSession] = useState(false);

  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [platformExpanded, setPlatformExpanded] = useState(false);
  const [menuState, setMenuState] = useState<{
    path: string;
    mobile: boolean;
    org: boolean;
    user: boolean;
    alerts: boolean;
  }>({ path: pathname, mobile: false, org: false, user: false, alerts: false });
  const mobileMenuOpen = menuState.path === pathname && menuState.mobile;
  const orgMenuOpen = menuState.path === pathname && menuState.org;
  const userMenuOpen = menuState.path === pathname && menuState.user;
  const alertsOpen = menuState.path === pathname && menuState.alerts;

  const updateMenuFlag = useCallback(
    (key: "mobile" | "org" | "user" | "alerts", val: boolean | ((prev: boolean) => boolean)) => {
      setMenuState((prev) => {
        const base =
          prev.path === pathname
            ? prev
            : { path: pathname, mobile: false, org: false, user: false, alerts: false };
        const next = typeof val === "function" ? val(base[key]) : val;
        return { ...base, [key]: next };
      });
    },
    [pathname],
  );
  const setMobileMenuOpen = useCallback(
    (val: boolean | ((prev: boolean) => boolean)) => updateMenuFlag("mobile", val),
    [updateMenuFlag],
  );
  const setOrgMenuOpen = useCallback(
    (val: boolean | ((prev: boolean) => boolean)) => updateMenuFlag("org", val),
    [updateMenuFlag],
  );
  const setUserMenuOpen = useCallback(
    (val: boolean | ((prev: boolean) => boolean)) => updateMenuFlag("user", val),
    [updateMenuFlag],
  );
  const setAlertsOpen = useCallback(
    (val: boolean | ((prev: boolean) => boolean)) => updateMenuFlag("alerts", val),
    [updateMenuFlag],
  );
  const [switchingOrgId, setSwitchingOrgId] = useState<string | null>(null);
  const orgMenuRef = useRef<HTMLDivElement | null>(null);
  const alertsMenuRef = useRef<HTMLDivElement | null>(null);
  const userMenuRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!orgMenuOpen && !alertsOpen && !userMenuOpen && !mobileMenuOpen) {
      return;
    }

    const handlePointerDown = (e: PointerEvent) => {
      const target = e.target as Node | null;
      if (!target) return;
      if (orgMenuOpen && orgMenuRef.current && !orgMenuRef.current.contains(target)) {
        setOrgMenuOpen(false);
      }
      if (alertsOpen && alertsMenuRef.current && !alertsMenuRef.current.contains(target)) {
        setAlertsOpen(false);
      }
      if (userMenuOpen && userMenuRef.current && !userMenuRef.current.contains(target)) {
        setUserMenuOpen(false);
      }
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOrgMenuOpen(false);
        setAlertsOpen(false);
        setUserMenuOpen(false);
        setMobileMenuOpen(false);
      }
    };

    document.addEventListener("pointerdown", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("pointerdown", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [
    orgMenuOpen,
    alertsOpen,
    userMenuOpen,
    mobileMenuOpen,
    setOrgMenuOpen,
    setAlertsOpen,
    setUserMenuOpen,
    setMobileMenuOpen,
  ]);

  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string>("all");
  const [signals, setSignals] = useState<PostureSignal[]>([]);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  const loadAuth = useCallback(async () => {
    try {
      const me = await apiFetch<AuthMe>("/api/v1/auth/me", {
        signal: AbortSignal.timeout(20_000),
      });
      setAuth(me);
      setError(null);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setError("Authentication required. Please sign in to continue.");
        setLoading(false);
        router.replace("/login");
        return;
      }
      setError(err instanceof Error ? err.message : "Failed to load session");
    } finally {
      setLoading(false);
    }
  }, [router]);

  useEffect(() => {
    let active = true;
    void apiFetch<AuthMe>("/api/v1/auth/me", {
      signal: AbortSignal.timeout(20_000),
    })
      .then((me) => {
        if (!active) return;
        setAuth(me);
        setError(null);
        setLoading(false);
      })
      .catch((err) => {
        if (!active) return;
        if (err instanceof ApiError && err.status === 401) {
          setError("Authentication required. Please sign in to continue.");
          setLoading(false);
          router.replace("/login");
          return;
        }
        setError(err instanceof Error ? err.message : "Failed to load session");
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [router]);

  const membership = useMemo(
    () => auth?.memberships.find((m) => m.organization_id === orgId) || null,
    [auth, orgId],
  );

  useEffect(() => {
    if (!auth || !membership) return;
    let active = true;
    const canProjects = hasPermission(membership, "project:read");
    const canScans = hasPermission(membership, "scan:read");
    const canFindings = hasPermission(membership, "finding:read");
    const canIntel = hasPermission(membership, "intel:read");
    const canRunners = hasPermission(membership, "runner:read");

    void Promise.all([
      canProjects
        ? apiFetch<PaginatedResponse<Project>>(
            `/api/v1/organizations/${orgId}/projects?limit=100`,
          ).catch(() => null)
        : Promise.resolve(null),
      canScans
        ? apiFetch<PaginatedResponse<ScanRunSummary>>(
            `/api/v1/organizations/${orgId}/scans?limit=20`,
          ).catch(() => null)
        : Promise.resolve(null),
      canFindings
        ? apiFetch<PaginatedResponse<FindingItem>>(
            `/api/v1/organizations/${orgId}/findings?status=open&limit=50`,
          ).catch(() => null)
        : Promise.resolve(null),
      canIntel
        ? apiFetch<OrgThreatIntelSummary>(
            `/api/v1/organizations/${orgId}/intel/summary`,
          ).catch(() => null)
        : Promise.resolve(null),
      canRunners
        ? apiFetch<RunnerItem[]>(
            `/api/v1/organizations/${orgId}/runners`,
          ).catch(() => null)
        : Promise.resolve(null),
    ]).then(([projRes, scansRes, findingsRes, intelRes, runnersRes]) => {
      if (!active) return;
      if (projRes) {
        setProjects(projRes.items);
      }
      const nextSignals: PostureSignal[] = [];

      const slaBreached = (findingsRes?.items ?? []).filter(
        (f) => f.sla_breached,
      ).length;
      if (slaBreached > 0) {
        nextSignals.push({
          id: "sla-breach",
          title: `${slaBreached} open finding${slaBreached === 1 ? "" : "s"} breached SLA`,
          detail: "Review overdue findings and remediation targets.",
          href: `/organizations/${orgId}/findings`,
          tone: "danger",
        });
      }

      const failedScans = (scansRes?.items ?? []).filter((s) =>
        ["failed", "completed_with_errors"].includes(s.status),
      ).length;
      if (failedScans > 0) {
        nextSignals.push({
          id: "scan-errors",
          title: `${failedScans} recent scan run${failedScans === 1 ? "" : "s"} need attention`,
          detail: "Inspect stage status, coverage gaps, or failure logs.",
          href: `/organizations/${orgId}/scans`,
          tone: "warning",
        });
      }

      const staleFeeds = (intelRes?.sources ?? []).filter(
        (src) => src.is_active && src.is_stale,
      ).length;
      if (staleFeeds > 0) {
        nextSignals.push({
          id: "stale-intel",
          title: `${staleFeeds} threat intelligence feed${staleFeeds === 1 ? " is" : "s are"} stale`,
          detail: "Synchronize KEV/EPSS/NVD feeds for up-to-date enrichment.",
          href: `/organizations/${orgId}/threat-intel`,
          tone: "warning",
        });
      }

      const activeRunners = (runnersRes ?? []).filter(
        (r) => r.status === "active",
      ).length;
      if (canRunners && runnersRes !== null && runnersRes.length > 0 && activeRunners === 0) {
        nextSignals.push({
          id: "no-active-runners",
          title: "No active runners online",
          detail: "Registered runners are offline or revoked.",
          href: `/organizations/${orgId}/runners`,
          tone: "info",
        });
      }

      setSignals(nextSignals);
    });

    return () => {
      active = false;
    };
  }, [auth, membership, orgId]);

  const handleSignOut = async () => {
    setSigningOut(true);
    try {
      await signOutAndRedirect({
        csrfToken: auth?.csrf_token,
        onLocalRedirect: () => router.replace("/login"),
      });
    } catch (err) {
      setActionNotice(err instanceof Error ? err.message : "Logout failed");
      setSigningOut(false);
    }
  };

  const handleSwitchOrg = async (targetOrgId: string) => {
    if (targetOrgId === orgId || !auth) {
      setOrgMenuOpen(false);
      return;
    }
    setSwitchingOrgId(targetOrgId);
    try {
      await apiFetch("/api/v1/auth/switch-organization", {
        method: "POST",
        csrfToken: auth.csrf_token,
        body: JSON.stringify({ organization_id: targetOrgId }),
      });
      setOrgMenuOpen(false);
      router.push(`/organizations/${targetOrgId}`);
    } catch (err) {
      setActionNotice(
        err instanceof Error ? err.message : "Failed to switch organization",
      );
    } finally {
      setSwitchingOrgId(null);
    }
  };

  const handleRotateSession = async () => {
    if (!auth) return;
    setRotatingSession(true);
    try {
      await apiFetch("/api/v1/auth/session/rotate", {
        method: "POST",
        csrfToken: auth.csrf_token,
      });
      await loadAuth();
      setActionNotice("Session and CSRF tokens rotated cleanly.");
      setUserMenuOpen(false);
    } catch (err) {
      setActionNotice(
        err instanceof Error ? err.message : "Session rotation failed",
      );
    } finally {
      setRotatingSession(false);
    }
  };

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[#111113] px-6 text-sm text-zinc-400">
        Verifying session and workspace context...
      </div>
    );
  }

  if (error || !auth) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[#09090b] px-6 py-16">
        <div className="w-full max-w-lg rounded-2xl border border-white/[0.08] bg-[#141418] p-6 text-zinc-100 shadow-2xl">
          <h1 className="text-lg font-semibold text-white">Session or Access Required</h1>
          <p className="mt-2 text-xs leading-relaxed text-zinc-400">
            {error || "Sign in to access this workspace."}
          </p>
          <div className="mt-5 flex flex-wrap gap-3">
            <Link
              href="/login"
              className="vf-btn-primary h-8 px-4 text-xs"
            >
              Sign In
            </Link>
            <Link
              href="/organizations?manage=1"
              className="vf-btn-secondary h-8 px-4 text-xs"
            >
              Manage Organizations
            </Link>
          </div>
        </div>
      </div>
    );
  }

  const orgName = membership
    ? membership.organization_name
    : `Tenant ${orgId.slice(0, 8)}`;

  const permittedNavItems = WORKSPACE_NAV_ITEMS.filter(
    (item) =>
      !item.requiredPermission ||
      hasPermission(membership, item.requiredPermission),
  );
  const breadcrumbs = resolveBreadcrumbs(orgId, pathname, orgName);

  const isPlatformRouteActive = WORKSPACE_NAV_ITEMS.some(
    (item) =>
      item.group === "Platform & Admin" &&
      (pathname === `/organizations/${orgId}/${item.segment}` ||
        pathname.startsWith(`/organizations/${orgId}/${item.segment}/`)),
  );
  const showPlatformAdmin = platformExpanded || isPlatformRouteActive;
  const canStartScan = hasPermission(membership, "scan:read");

  const initials =
    auth.user.display_name
      .split(/\s+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((part) => part[0]?.toUpperCase() ?? "")
      .join("") || "VF";

  const renderNavContent = (collapsed: boolean, isMobile = false) => (
    <div className="flex h-full flex-col bg-[#121214]">
      <div className="flex h-11 items-center justify-between border-b border-white/[0.06] px-3.5">
        <Link
          href={`/organizations/${orgId}`}
          className="flex items-center gap-2 overflow-hidden"
        >
          <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-white/[0.08] text-zinc-100">
            <ShieldCheck className="h-3.5 w-3.5" />
          </div>
          {!collapsed ? (
            <span className="truncate text-[13px] font-semibold tracking-tight text-zinc-100">
              VForge
            </span>
          ) : null}
        </Link>
        <button
          type="button"
          onClick={() => setMobileMenuOpen(false)}
          className="rounded-md p-1 text-zinc-400 hover:bg-white/[0.06] hover:text-white lg:hidden"
          aria-label="Close sidebar"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      {canStartScan ? (
        <div className="px-2.5 pt-2.5">
          <Link
            href={`/organizations/${orgId}/scans`}
            title={collapsed ? "Start New Scan" : undefined}
            className={cn(
              "vf-btn-sidebar h-9 w-full text-[13px]",
              collapsed ? "justify-center px-0" : "px-3",
            )}
          >
            <Plus className="h-4 w-4 shrink-0 text-zinc-300" />
            {!collapsed ? <span>Start New Scan</span> : null}
          </Link>
        </div>
      ) : null}

      {isMobile && projects.length > 0 ? (
        <div className="px-2.5 pt-2.5 sm:hidden">
          <label className="mb-1 block px-1 text-[10px] font-medium uppercase tracking-wider text-zinc-500">
            Project Scope
          </label>
          <Select
            aria-label="Mobile project context"
            size="sm"
            value={selectedProjectId}
            onValueChange={setSelectedProjectId}
            className="bg-[#18181c]"
          >
            <option value="all">All Projects ({projects.length})</option>
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </Select>
        </div>
      ) : null}

      <nav
        aria-label="Workspace navigation"
        className="flex-1 space-y-4 overflow-y-auto px-2 py-3"
      >
        {NAV_GROUPS.map((group) => {
          const items = permittedNavItems.filter(
            (item) => item.group === group && item.id !== "settings",
          );
          if (items.length === 0) return null;
          const isCollapsible = group === "Platform & Admin";
          const isOpen = !isCollapsible || collapsed || showPlatformAdmin;
          const groupLabel =
            group === "Start Here (Workflow)"
              ? "Workflow"
              : group === "Scan Rules & Intel"
                ? "Security & Intel"
                : "Platform";

          return (
            <div key={group}>
              {!collapsed ? (
                isCollapsible ? (
                  <button
                    type="button"
                    onClick={() => setPlatformExpanded((prev) => !prev)}
                    className="mb-1 flex w-full items-center justify-between px-2.5 py-1 text-[11px] font-medium text-zinc-500 transition hover:text-zinc-300"
                  >
                    <span>{groupLabel}</span>
                    <ChevronDown
                      className={cn(
                        "h-3 w-3 transition-transform",
                        isOpen ? "rotate-0" : "-rotate-90",
                      )}
                    />
                  </button>
                ) : (
                  <div className="mb-1 px-2.5 text-[11px] font-medium text-zinc-500">
                    {groupLabel}
                  </div>
                )
              ) : null}
              {isOpen ? (
                <div className="space-y-0.5">
                  {items.map((item) => {
                    const href = item.segment
                      ? `/organizations/${orgId}/${item.segment}`
                      : `/organizations/${orgId}`;
                    const active =
                      item.segment === ""
                        ? pathname === href
                        : pathname === href || pathname.startsWith(`${href}/`);
                    const Icon = ICON_MAP[item.icon] ?? LayoutDashboard;
                    return (
                      <Link
                        key={item.id}
                        href={href}
                        title={collapsed ? item.label : undefined}
                        className={cn(
                          "flex items-center justify-between gap-2 rounded-lg px-2.5 py-1.5 text-[13px] transition",
                          collapsed ? "justify-center px-2" : "",
                          active
                            ? "bg-white/[0.08] font-medium text-white"
                            : "text-zinc-400 hover:bg-white/[0.04] hover:text-zinc-100",
                        )}
                      >
                        <span className="flex min-w-0 items-center gap-2.5">
                          <Icon
                            className={cn(
                              "h-4 w-4 shrink-0",
                              active ? "text-zinc-100" : "text-zinc-500",
                            )}
                          />
                          {!collapsed ? (
                            <span className="truncate">{item.label}</span>
                          ) : null}
                        </span>
                        {!collapsed && item.tag ? (
                          <span className="shrink-0 text-[11px] text-zinc-600 tabular-nums">
                            {item.tag}
                          </span>
                        ) : null}
                      </Link>
                    );
                  })}
                </div>
              ) : null}
            </div>
          );
        })}
      </nav>

      <div className="border-t border-white/[0.05] px-2 py-2">
        {!collapsed ? (
          <Link
            href={`/organizations/${orgId}/settings`}
            className={cn(
              "flex items-center justify-between rounded-lg px-2.5 py-1.5 text-[13px] transition",
              pathname === `/organizations/${orgId}/settings`
                ? "bg-white/[0.08] font-medium text-white"
                : "text-zinc-400 hover:bg-white/[0.04] hover:text-zinc-100",
            )}
          >
            <span className="flex items-center gap-2.5">
              <Settings className="h-4 w-4 shrink-0 text-zinc-500" />
              <span>Settings</span>
            </span>
            <span className="text-[11px] text-zinc-500">
              {membership ? membership.role.replaceAll("_", " ") : "guest"}
            </span>
          </Link>
        ) : (
          <Link
            href={`/organizations/${orgId}/settings`}
            title={`Settings (${membership?.role ?? "unassigned"})`}
            className="flex justify-center rounded-lg p-2 text-zinc-400 hover:bg-white/[0.04] hover:text-white"
          >
            <Settings className="h-4 w-4" />
          </Link>
        )}
      </div>
    </div>
  );

  return (
    <OrgWorkspaceContext.Provider
      value={{ orgId, projects, selectedProjectId, setSelectedProjectId }}
    >
      <div className="flex min-h-screen bg-[#09090b] text-zinc-100">
        {/* Desktop Sidebar */}
        <aside
          className={cn(
            "hidden shrink-0 border-r border-white/[0.06] bg-[#121214] transition-all duration-150 lg:block",
            sidebarCollapsed ? "w-[64px]" : "w-[240px]",
          )}
        >
          <div className="sticky top-0 h-screen">
            {renderNavContent(sidebarCollapsed)}
          </div>
        </aside>

        {/* Mobile Drawer */}
        {mobileMenuOpen ? (
          <div className="fixed inset-0 z-50 flex lg:hidden">
            <div
              className="fixed inset-0 bg-black/80 backdrop-blur-xs"
              onClick={() => setMobileMenuOpen(false)}
            />
            <aside className="relative z-10 h-full w-64 max-w-[82vw] border-r border-white/[0.06] bg-[#121214]">
              {renderNavContent(false, true)}
            </aside>
          </div>
        ) : null}

        {/* Right Main Column */}
        <div className="flex min-w-0 flex-1 flex-col bg-[#09090b]">
          <header className="sticky top-0 z-30 border-b border-white/[0.05] bg-[#09090b]/92 backdrop-blur-md">
            <div className="flex h-11 items-center justify-between gap-2 px-3 sm:gap-3 sm:px-6">
              <div className="flex min-w-0 flex-1 items-center gap-2 overflow-hidden">
                <button
                  type="button"
                  onClick={() => setMobileMenuOpen(true)}
                  className="vf-btn-ghost p-1.5 lg:hidden"
                  aria-label="Open menu"
                >
                  <Menu className="h-4 w-4" />
                </button>
                <button
                  type="button"
                  onClick={() => setSidebarCollapsed((prev) => !prev)}
                  className="vf-btn-ghost hidden p-1.5 lg:inline-flex"
                  aria-label={
                    sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"
                  }
                >
                  {sidebarCollapsed ? (
                    <PanelLeftOpen className="h-4 w-4" />
                  ) : (
                    <PanelLeftClose className="h-4 w-4" />
                  )}
                </button>

                {/* VForge Studio Breadcrumbs — concise on compact/split viewports, full on xl+ */}
                <nav
                  aria-label="Breadcrumb"
                  className="hidden min-w-0 items-center gap-1.5 overflow-hidden text-[13px] sm:flex"
                >
                  <span className="truncate font-medium text-zinc-200 xl:hidden">
                    {breadcrumbs[breadcrumbs.length - 1]?.label ?? orgName}
                  </span>
                  <div className="hidden min-w-0 items-center gap-1.5 xl:flex">
                    {breadcrumbs.map((crumb, idx) => (
                      <span
                        key={`${crumb.label}-${idx}`}
                        className="flex min-w-0 items-center gap-1.5"
                      >
                        {idx > 0 ? (
                          <span className="text-zinc-600">/</span>
                        ) : null}
                        {crumb.href ? (
                          <Link
                            href={crumb.href}
                            className="truncate text-zinc-400 transition hover:text-zinc-100"
                          >
                            {crumb.label}
                          </Link>
                        ) : (
                          <span
                            className={cn(
                              "truncate",
                              idx === breadcrumbs.length - 1
                                ? "font-medium text-zinc-200"
                                : "text-zinc-500",
                            )}
                          >
                            {crumb.label}
                          </span>
                        )}
                      </span>
                    ))}
                  </div>
                </nav>
              </div>

              {/* Right Context & Profile Controls */}
              <div className="flex shrink-0 items-center gap-1 sm:gap-1.5">
                {/* Organization Switcher */}
                <div ref={orgMenuRef} className="relative">
                  <button
                    type="button"
                    aria-expanded={orgMenuOpen}
                    aria-haspopup="menu"
                    onClick={() => {
                      setOrgMenuOpen((prev) => !prev);
                      setAlertsOpen(false);
                      setUserMenuOpen(false);
                    }}
                    className="vf-btn-ghost h-7 px-2.5 text-xs text-zinc-300"
                  >
                    <Building2 className="h-3.5 w-3.5 text-zinc-400" />
                    <span className="max-w-[96px] truncate sm:max-w-[140px]">
                      {orgName}
                    </span>
                    <ChevronDown className="h-3 w-3 text-zinc-500" />
                  </button>
                  {orgMenuOpen ? (
                    <div className="absolute right-0 mt-1.5 w-64 max-w-[calc(100vw-2rem)] rounded-2xl border border-white/[0.08] bg-[#151518] p-1.5 shadow-2xl">
                      <div className="px-2.5 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
                        Switch Tenant
                      </div>
                      <div className="max-h-60 space-y-0.5 overflow-y-auto">
                        {auth.memberships.map((m) => (
                          <button
                            key={m.organization_id}
                            type="button"
                            disabled={switchingOrgId !== null}
                            onClick={() => void handleSwitchOrg(m.organization_id)}
                            className="flex w-full items-center justify-between rounded-lg px-2.5 py-2 text-left text-xs text-zinc-200 hover:bg-white/[0.06]"
                          >
                            <div className="min-w-0">
                              <div className="truncate font-medium">
                                {m.organization_name}
                              </div>
                              <div className="text-[11px] text-zinc-400">
                                {m.role}
                              </div>
                            </div>
                            {m.organization_id === orgId ? (
                              <Check className="h-3.5 w-3.5 shrink-0 text-blue-400" />
                            ) : null}
                          </button>
                        ))}
                      </div>
                      <div className="mt-1 border-t border-white/[0.07] pt-1">
                        <Link
                          href="/organizations?manage=1"
                          onClick={() => setOrgMenuOpen(false)}
                          className="block rounded-lg px-2.5 py-1.5 text-xs font-medium text-blue-400 hover:bg-white/[0.06]"
                        >
                          Manage All Organizations
                        </Link>
                      </div>
                    </div>
                  ) : null}
                </div>

                {/* Project Context Filter */}
                {projects.length > 0 ? (
                  <div className="hidden shrink-0 sm:block">
                    <Select
                      aria-label="Project context"
                      size="sm"
                      icon={<FolderKanban className="h-3.5 w-3.5" />}
                      value={selectedProjectId}
                      onValueChange={setSelectedProjectId}
                      className="h-7 w-auto max-w-[180px] border-white/[0.08] bg-[#16161b] py-0 text-xs"
                    >
                      <option value="all">
                        All Projects ({projects.length})
                      </option>
                      {projects.map((p) => (
                        <option key={p.id} value={p.id}>
                          {p.name}
                        </option>
                      ))}
                    </Select>
                  </div>
                ) : null}

                {/* Theme Switcher */}
                <ThemeToggle variant="icon" />

                {/* Posture Alerts Bell */}
                <div ref={alertsMenuRef} className="relative">
                  <button
                    type="button"
                    aria-label="Security posture notifications"
                    aria-expanded={alertsOpen}
                    aria-haspopup="dialog"
                    onClick={() => {
                      setAlertsOpen((prev) => !prev);
                      setOrgMenuOpen(false);
                      setUserMenuOpen(false);
                    }}
                    className="vf-btn-ghost relative h-7 w-7 p-0"
                  >
                    <Bell className="h-3.5 w-3.5" />
                    {signals.length > 0 ? (
                      <span
                        className="absolute top-1.5 right-1.5 h-1.5 w-1.5 rounded-full bg-blue-500"
                        aria-label={`${signals.length} posture alerts`}
                      />
                    ) : null}
                  </button>
                  {alertsOpen ? (
                    <div className="fixed inset-x-4 top-12 mt-1 rounded-2xl border border-white/[0.08] bg-[#151518] p-3 shadow-2xl sm:absolute sm:inset-x-auto sm:top-auto sm:right-0 sm:mt-1.5 sm:w-80">
                      <div className="flex items-center justify-between border-b border-white/[0.07] pb-2">
                        <span className="text-xs font-semibold text-white">
                          Control-Plane Signals
                        </span>
                        <Badge tone={signals.length > 0 ? "warning" : "success"}>
                          {signals.length > 0
                            ? `${signals.length} active`
                            : "All clear"}
                        </Badge>
                      </div>
                      <div className="mt-2 space-y-2">
                        {signals.length === 0 ? (
                          <p className="py-2 text-xs text-zinc-400">
                            No SLA breaches, failed scans, or stale feeds detected.
                          </p>
                        ) : (
                          signals.map((sig) => (
                            <Link
                              key={sig.id}
                              href={sig.href}
                              onClick={() => setAlertsOpen(false)}
                              className="block rounded-lg border border-white/[0.07] bg-[#131316] p-2.5 hover:border-white/[0.15]"
                            >
                              <div className="flex items-start gap-2">
                                <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-400" />
                                <div>
                                  <p className="text-xs font-medium text-white">
                                    {sig.title}
                                  </p>
                                  <p className="mt-0.5 text-[11px] text-zinc-400">
                                    {sig.detail}
                                  </p>
                                </div>
                              </div>
                            </Link>
                          ))
                        )}
                      </div>
                      <p className="mt-2.5 border-t border-white/[0.07] pt-2 text-[10px] text-zinc-500">
                        Live API posture feed. External webhook/email alerts are planned.
                      </p>
                    </div>
                  ) : null}
                </div>

                {/* User Profile & Session Menu */}
                <div ref={userMenuRef} className="relative">
                  <button
                    type="button"
                    aria-expanded={userMenuOpen}
                    aria-haspopup="menu"
                    onClick={() => {
                      setUserMenuOpen((prev) => !prev);
                      setOrgMenuOpen(false);
                      setAlertsOpen(false);
                    }}
                    className="vf-btn-ghost h-7 gap-1.5 px-2 text-left"
                  >
                    <span className="flex h-5 w-5 items-center justify-center rounded-full bg-white/[0.1] text-[10px] font-semibold text-zinc-200">
                      {initials}
                    </span>
                    <span className="hidden max-w-[110px] truncate text-xs text-zinc-300 sm:inline">
                      {auth.user.display_name}
                    </span>
                    <ChevronDown className="h-3 w-3 text-zinc-500" />
                  </button>
                  {userMenuOpen ? (
                    <div className="absolute right-0 mt-1.5 w-72 max-w-[calc(100vw-1.5rem)] rounded-2xl border border-white/[0.08] bg-[#151518] p-2 shadow-2xl">
                      <div className="border-b border-white/[0.07] px-2 pb-2.5">
                        <div className="truncate text-xs font-semibold text-white">
                          {auth.user.display_name}
                        </div>
                        <div className="truncate text-[11px] text-zinc-400">
                          {auth.user.email}
                        </div>
                        {membership ? (
                          <div className="mt-1.5">
                            <Badge tone="info">
                              {membership.role.replaceAll("_", " ")}
                            </Badge>
                          </div>
                        ) : null}
                      </div>
                      <div className="mt-1.5 space-y-0.5 text-xs">
                        <div className="space-y-1.5 px-2 py-1.5">
                          <div className="flex items-center justify-between gap-2 text-[11px]">
                            <span className="font-medium text-zinc-400">
                              Theme
                            </span>
                            <span className="capitalize text-zinc-500">
                              {theme === "system"
                                ? `System (${resolvedTheme})`
                                : resolvedTheme}
                            </span>
                          </div>
                          <ThemeToggle variant="segmented" fullWidth />
                        </div>
                        <div className="my-1 border-t border-white/[0.07]" />
                        <Link
                          href={`/organizations/${orgId}/settings`}
                          onClick={() => setUserMenuOpen(false)}
                          className="flex items-center gap-2 rounded-lg px-2.5 py-2 text-zinc-200 hover:bg-white/[0.06]"
                        >
                          <Settings className="h-3.5 w-3.5 text-zinc-400" />
                          Workspace Settings
                        </Link>
                        <button
                          type="button"
                          onClick={() => void handleRotateSession()}
                          disabled={rotatingSession}
                          className="flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-left text-zinc-200 hover:bg-white/[0.06] disabled:opacity-50"
                        >
                          <RefreshCw className="h-3.5 w-3.5 text-zinc-400" />
                          {rotatingSession
                            ? "Rotating session..."
                            : "Rotate Session Token"}
                        </button>
                        <Link
                          href="/organizations?manage=1"
                          onClick={() => setUserMenuOpen(false)}
                          className="flex items-center gap-2 rounded-lg px-2.5 py-2 text-zinc-200 hover:bg-white/[0.06]"
                        >
                          <Building2 className="h-3.5 w-3.5 text-zinc-400" />
                          All Organizations
                        </Link>
                        <button
                          type="button"
                          onClick={handleSignOut}
                          disabled={signingOut}
                          className="flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-left text-zinc-300 transition hover:bg-rose-500/10 hover:text-rose-300 disabled:opacity-50"
                        >
                          <LogOut className="h-3.5 w-3.5" />
                          {signingOut ? "Signing out..." : "Sign Out"}
                        </button>
                      </div>
                    </div>
                  ) : null}
                </div>
              </div>
            </div>
          </header>

          {actionNotice ? (
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.07] bg-[#18181b] px-4 py-2 text-xs text-zinc-200 sm:px-6">
              <span>{actionNotice}</span>
              <button
                type="button"
                onClick={() => setActionNotice(null)}
                className="text-zinc-400 hover:text-white"
              >
                Dismiss
              </button>
            </div>
          ) : null}

          <main className="mx-auto w-full max-w-[1440px] flex-1 px-4 py-6 sm:px-6 lg:px-8">
            {children({ auth, membership, reloadAuth: loadAuth })}
          </main>
        </div>
      </div>
    </OrgWorkspaceContext.Provider>
  );
}
