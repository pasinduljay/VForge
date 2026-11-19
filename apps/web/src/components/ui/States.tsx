import Link from "next/link";
import type { ReactNode } from "react";
import { AlertCircle, CheckCircle2, Clock, Info, ShieldAlert } from "lucide-react";
import { cn } from "@/lib/cn";

export function EmptyState({
  icon,
  title,
  description,
  actionLabel,
  actionHref,
  onAction,
}: {
  icon?: ReactNode;
  title: string;
  description: string;
  actionLabel?: string;
  actionHref?: string;
  onAction?: () => void;
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-white/[0.05] bg-[#101013]/60 px-5 py-8 text-center">
      {icon ? (
        <div className="mb-2.5 text-zinc-400">
          {icon}
        </div>
      ) : null}
      <h3 className="text-[13px] font-semibold text-zinc-100">{title}</h3>
      <p className="mt-1 max-w-md text-xs leading-relaxed text-zinc-400">
        {description}
      </p>
      {actionLabel && actionHref ? (
        <Link
          href={actionHref}
          className="vf-btn-secondary mt-4 rounded-full px-4 py-1.5 text-xs"
        >
          {actionLabel}
        </Link>
      ) : actionLabel && onAction ? (
        <button
          type="button"
          onClick={onAction}
          className="vf-btn-secondary mt-4 rounded-full px-4 py-1.5 text-xs"
        >
          {actionLabel}
        </button>
      ) : null}
    </div>
  );
}

export type BannerTone = "info" | "warning" | "error" | "success" | "planned";

const BANNER_STYLES: Record<BannerTone, string> = {
  info: "border-white/[0.08] bg-[#131317] text-zinc-200",
  warning: "border-white/[0.085] bg-[#131317] text-zinc-200",
  error: "border-white/[0.085] bg-[#131317] text-zinc-200",
  success: "border-white/[0.085] bg-[#131317] text-zinc-200",
  planned: "border-white/[0.07] bg-[#121215] text-zinc-300",
};

const ICON_TONE: Record<BannerTone, string> = {
  info: "text-[#5b8ef8]",
  warning: "text-amber-400/90",
  error: "text-rose-400/90",
  success: "text-emerald-400/90",
  planned: "text-zinc-500",
};

export function NoticeBanner({
  tone = "info",
  title,
  message,
  onRetry,
  className,
}: {
  tone?: BannerTone;
  title?: string;
  message: string;
  onRetry?: () => void;
  className?: string;
}) {
  const Icon =
    tone === "error"
      ? ShieldAlert
      : tone === "warning"
        ? AlertCircle
        : tone === "success"
          ? CheckCircle2
          : tone === "planned"
            ? Clock
            : Info;

  return (
    <div
      className={cn(
        "flex flex-wrap items-start justify-between gap-3 rounded-xl border px-4 py-3 text-sm shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]",
        BANNER_STYLES[tone],
        className,
      )}
    >
      <div className="flex items-start gap-2.5">
        <Icon className={cn("mt-0.5 h-4 w-4 shrink-0", ICON_TONE[tone])} />
        <div>
          {title ? <p className="text-xs font-semibold text-zinc-100">{title}</p> : null}
          <p className={cn("text-xs leading-relaxed text-zinc-300", title ? "mt-0.5 text-zinc-400" : "")}>
            {message}
          </p>
        </div>
      </div>
      {onRetry ? (
        <button
          type="button"
          onClick={onRetry}
          className="vf-btn-secondary px-3 py-1 text-xs"
        >
          Retry
        </button>
      ) : null}
    </div>
  );
}
