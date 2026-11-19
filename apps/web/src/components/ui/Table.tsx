import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

export function DataTableWrapper({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("overflow-x-auto", className)}>
      <table className="min-w-full divide-y divide-white/[0.07] text-left text-sm">
        {children}
      </table>
    </div>
  );
}

export function Th({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <th
      scope="col"
      className={cn(
        "whitespace-nowrap bg-[#141417] px-4 py-2.5 text-xs font-medium tracking-normal text-zinc-400",
        className,
      )}
    >
      {children}
    </th>
  );
}

export function Td({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <td className={cn("px-4 py-3 align-top text-[13px] leading-relaxed text-zinc-200", className)}>
      {children}
    </td>
  );
}
