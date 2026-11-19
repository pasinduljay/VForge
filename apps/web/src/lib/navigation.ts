export interface NavItemConfig {
  id: string;
  label: string;
  segment: string; // "" for overview, otherwise path segment under /organizations/[orgId]/
  group: "Start Here (Workflow)" | "Scan Rules & Intel" | "Platform & Admin";
  icon: string;
  tag?: string;
  requiredPermission?: string;
}

export const WORKSPACE_NAV_ITEMS: NavItemConfig[] = [
  // Group 1: Cloud-engineer step-by-step workflow
  {
    id: "overview",
    label: "Overview",
    segment: "",
    group: "Start Here (Workflow)",
    icon: "LayoutDashboard",
    requiredPermission: "org:read",
  },
  {
    id: "projects",
    label: "Projects",
    segment: "projects",
    group: "Start Here (Workflow)",
    icon: "FolderKanban",
    requiredPermission: "project:read",
  },
  {
    id: "assets",
    label: "Targets & Assets",
    segment: "assets",
    group: "Start Here (Workflow)",
    icon: "Server",
    requiredPermission: "asset:read",
  },
  {
    id: "authorizations",
    label: "Scan Approvals",
    segment: "authorizations",
    group: "Start Here (Workflow)",
    icon: "ShieldCheck",
    requiredPermission: "authorization:read",
  },
  {
    id: "scans",
    label: "Scan Center",
    segment: "scans",
    group: "Start Here (Workflow)",
    icon: "PlayCircle",
    requiredPermission: "scan:read",
  },
  {
    id: "findings",
    label: "Issues & Fixes",
    segment: "findings",
    group: "Start Here (Workflow)",
    icon: "Bug",
    requiredPermission: "finding:read",
  },
  {
    id: "reports",
    label: "Reports",
    segment: "reports",
    group: "Start Here (Workflow)",
    icon: "FileText",
    requiredPermission: "report:read",
  },

  // Group 2: Scan configuration & security feeds
  {
    id: "scan-profiles",
    label: "Scan Profiles",
    segment: "scan-profiles",
    group: "Scan Rules & Intel",
    icon: "SlidersHorizontal",
    requiredPermission: "scan_profile:read",
  },
  {
    id: "scope",
    label: "Scope Rules",
    segment: "scope",
    group: "Scan Rules & Intel",
    icon: "Radar",
    requiredPermission: "snapshot:read",
  },
  {
    id: "evidence",
    label: "Evidence Vault",
    segment: "evidence",
    group: "Scan Rules & Intel",
    icon: "FileArchive",
    requiredPermission: "scan:read",
  },
  {
    id: "threat-intel",
    label: "Threat Intel (KEV)",
    segment: "threat-intel",
    group: "Scan Rules & Intel",
    icon: "Globe",
    requiredPermission: "intel:read",
  },
  {
    id: "supply-chain",
    label: "Supply Chain (SBOM)",
    segment: "supply-chain",
    group: "Scan Rules & Intel",
    icon: "PackageSearch",
    requiredPermission: "sbom:read",
  },

  // Group 3: Platform internals & tenant administration
  {
    id: "runners",
    label: "Runners Fleet",
    segment: "runners",
    group: "Platform & Admin",
    icon: "Cpu",
    requiredPermission: "runner:read",
  },
  {
    id: "updates",
    label: "Scanner Updates",
    segment: "updates",
    group: "Platform & Admin",
    icon: "RefreshCw",
    requiredPermission: "update:read",
  },
  {
    id: "studio",
    label: "Rule & AI Studio",
    segment: "studio",
    group: "Platform & Admin",
    icon: "Code2",
    requiredPermission: "studio:read",
  },
  {
    id: "ai-governance",
    label: "AI Governance",
    segment: "ai-governance",
    group: "Platform & Admin",
    icon: "Bot",
    requiredPermission: "ai:read",
  },
  {
    id: "lab",
    label: "Learning Lab",
    segment: "lab",
    group: "Platform & Admin",
    icon: "GraduationCap",
    requiredPermission: "lab:read",
  },
  {
    id: "redteam",
    label: "AI Red Team",
    segment: "redteam",
    group: "Platform & Admin",
    icon: "Swords",
    requiredPermission: "redteam:read",
  },
  {
    id: "members",
    label: "Users & Roles",
    segment: "members",
    group: "Platform & Admin",
    icon: "Users",
    requiredPermission: "membership:read",
  },
  {
    id: "audit",
    label: "Audit Logs",
    segment: "audit",
    group: "Platform & Admin",
    icon: "ScrollText",
    requiredPermission: "audit:read",
  },
  {
    id: "security-ops",
    label: "Security Ops & DR",
    segment: "security-ops",
    group: "Platform & Admin",
    icon: "KeyRound",
    requiredPermission: "hardening:read",
  },
  {
    id: "integrations",
    label: "Integrations",
    segment: "integrations",
    group: "Platform & Admin",
    icon: "Plug",
    requiredPermission: "org:read",
  },
  {
    id: "system-health",
    label: "System Health",
    segment: "system-health",
    group: "Platform & Admin",
    icon: "Activity",
    requiredPermission: "org:read",
  },
  {
    id: "settings",
    label: "Settings",
    segment: "settings",
    group: "Platform & Admin",
    icon: "Settings",
    requiredPermission: "org:read",
  },
];

export const NAV_GROUPS: Array<NavItemConfig["group"]> = [
  "Start Here (Workflow)",
  "Scan Rules & Intel",
  "Platform & Admin",
];
