import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

export type BadgeTone =
  | "neutral"
  | "success"
  | "warning"
  | "danger"
  | "info"
  | "purple"
  | "planned";

const TONE_STYLES: Record<BadgeTone, string> = {
  neutral: "border-white/[0.08] bg-[#19191e] text-zinc-300",
  success: "border-white/[0.085] bg-[#19191e] text-zinc-200",
  warning: "border-white/[0.085] bg-[#19191e] text-amber-300/90",
  danger: "border-white/[0.085] bg-[#19191e] text-rose-300/90",
  info: "border-white/[0.085] bg-[#19191e] text-[#93c5fd]",
  purple: "border-white/[0.085] bg-[#19191e] text-zinc-300",
  planned: "border-dashed border-white/[0.12] bg-[#131317] text-zinc-400",
};

const DOT_STYLES: Record<BadgeTone, string> = {
  neutral: "bg-zinc-400",
  success: "bg-emerald-400",
  warning: "bg-amber-400",
  danger: "bg-rose-400",
  info: "bg-[#5b8ef8]",
  purple: "bg-violet-400",
  planned: "bg-zinc-500",
};

export function Badge({
  tone = "neutral",
  dot = false,
  className,
  children,
}: {
  tone?: BadgeTone;
  dot?: boolean;
  className?: string;
  children: ReactNode;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 py-0.5 text-[11px] font-medium tracking-tight",
        TONE_STYLES[tone],
        className,
      )}
    >
      {dot && (
        <span
          className={cn("h-1.5 w-1.5 shrink-0 rounded-full", DOT_STYLES[tone])}
        />
      )}
      {children}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  const normalized = severity.toLowerCase();
  const tone: BadgeTone =
    normalized === "critical" || normalized === "high"
      ? "danger"
      : normalized === "medium"
        ? "warning"
        : normalized === "low"
          ? "info"
          : "neutral";
  return (
    <Badge tone={tone} dot className="uppercase font-semibold tracking-wider">
      {normalized === "critical" ? "CRIT" : severity.toUpperCase()}
    </Badge>
  );
}

export function statusToTone(status: string): BadgeTone {
  const normalized = status.toLowerCase();
  if (
    [
      "active",
      "approved",
      "completed",
      "fixed",
      "healthy",
      "online",
      "ok",
      "passed",
      "pass",
      "promoted",
      "stable",
      "valid",
      "verified",
      "confirmed",
    ].includes(normalized)
  ) {
    return "success";
  }
  if (
    [
      "running",
      "queued",
      "dispatched",
      "canary",
      "in_remediation",
      "pending_review",
      "pending",
      "pending_approval",
      "evaluating",
    ].includes(normalized)
  ) {
    return "info";
  }
  if (
    [
      "open",
      "completed_with_errors",
      "partial",
      "stale",
      "warning",
      "risk_accepted",
      "requested",
      "paused",
    ].includes(normalized)
  ) {
    return "warning";
  }
  if (
    [
      "failed",
      "error",
      "breached",
      "revoked",
      "offline",
      "quarantined",
      "denied",
      "rejected",
      "cancelled",
      "expired",
      "blocked",
    ].includes(normalized)
  ) {
    return "danger";
  }
  return "neutral";
}

export function StatusBadge({
  status,
  label,
}: {
  status: string;
  label?: string;
}) {
  return (
    <Badge tone={statusToTone(status)} dot className="capitalize">
      {label ?? status.replaceAll("_", " ")}
    </Badge>
  );
}
