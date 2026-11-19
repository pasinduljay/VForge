import Link from "next/link";
import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

export function Panel({
  className,
  children,
}: {
  className?: string;
  children: ReactNode;
}) {
  return (
    <section
      className={cn(
        "rounded-2xl border border-white/[0.068] bg-[#141417] p-5 shadow-[inset_0_1px_0_rgba(255,255,255,0.045)]",
        className,
      )}
    >
      {children}
    </section>
  );
}

export function SectionHeader({
  title,
  description,
  action,
  className,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "mb-4 flex items-start justify-between gap-4 border-b border-white/[0.06] pb-3.5",
        className,
      )}
    >
      <div className="min-w-0 flex-1">
        <h2 className="text-sm font-semibold tracking-tight text-zinc-100">
          {title}
        </h2>
        {description ? (
          <p className="mt-0.5 text-xs leading-relaxed text-zinc-400">
            {description}
          </p>
        ) : null}
      </div>
      {action ? (
        <div className="flex shrink-0 items-center gap-2 pt-0.5">{action}</div>
      ) : null}
    </div>
  );
}

export type StatTone = "default" | "success" | "warning" | "danger" | "info";

const ACCENT_CLASSES: Record<StatTone, string> = {
  default: "border-white/[0.068]",
  success: "border-white/[0.075]",
  warning: "border-white/[0.075]",
  danger: "border-white/[0.075]",
  info: "border-white/[0.075]",
};

export function StatCard({
  label,
  value,
  sublabel,
  icon,
  tone = "default",
  href,
}: {
  label: string;
  value: string | number;
  sublabel?: string;
  icon?: ReactNode;
  tone?: StatTone;
  href?: string;
}) {
  const inner = (
    <div
      className={cn(
        "flex h-full flex-col justify-between rounded-2xl border bg-[#141417] p-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] transition",
        ACCENT_CLASSES[tone],
        href ? "hover:border-white/[0.15] hover:bg-[#18181c]" : "",
      )}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs font-medium text-zinc-400">{label}</span>
        {icon ? <span className="text-zinc-500">{icon}</span> : null}
      </div>
      <div className="mt-2.5">
        <div className="text-2xl font-semibold tracking-tight text-white tabular-nums">
          {value}
        </div>
        {sublabel ? (
          <p className="mt-1 text-[11px] leading-relaxed text-zinc-500">
            {sublabel}
          </p>
        ) : null}
      </div>
    </div>
  );

  if (href) {
    return (
      <Link href={href} className="block h-full">
        {inner}
      </Link>
    );
  }
  return inner;
}
