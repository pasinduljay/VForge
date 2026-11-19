import Link from "next/link";
import { ArrowRight, FolderKanban, Radar, Shield, ShieldCheck } from "lucide-react";
import { PlatformStatusCard } from "@/components/PlatformStatusCard";
import { ThemeToggle } from "@/components/ThemeProvider";

const STEPS = [
  {
    step: "Step 1",
    icon: FolderKanban,
    title: "Add a Project & Target",
    description:
      "Organize apps or cloud services into Projects, then register URLs, domains, repositories, or container images.",
  },
  {
    step: "Step 2",
    icon: ShieldCheck,
    title: "Approve Safe Scan Scope",
    description:
      "Confirm testing ownership so automated scanners are strictly locked inside your approved target boundary.",
  },
  {
    step: "Step 3",
    icon: Radar,
    title: "Run Checks & Fix Issues",
    description:
      "Launch isolated scans in one click and review prioritized findings with clear remediation steps.",
  },
];

export default function HomePage() {
  return (
    <div className="min-h-screen bg-[#09090b] text-zinc-100">
      <header className="border-b border-white/[0.06] bg-[#09090b]/92 backdrop-blur-md">
        <div className="mx-auto flex h-12 max-w-5xl items-center justify-between px-6">
          <div className="flex items-center gap-2.5">
            <div className="flex h-6 w-6 items-center justify-center rounded-md bg-white/[0.08] text-zinc-100">
              <Shield className="h-3.5 w-3.5" />
            </div>
            <span className="text-[13px] font-semibold tracking-tight text-white">
              VForge
            </span>
          </div>
          <nav className="flex items-center gap-2">
            <ThemeToggle variant="icon" />
            <Link
              href="/login"
              className="vf-btn-ghost h-8 px-3 text-xs"
            >
              Sign In
            </Link>
            <Link
              href="/organizations"
              className="vf-btn-primary h-8 rounded-full px-3.5 text-xs"
            >
              Open Workspace
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </nav>
        </div>
      </header>

      <main className="mx-auto max-w-5xl space-y-10 px-6 py-14">
        <section className="max-w-2xl space-y-4">
          <div className="inline-flex items-center gap-2 rounded-full border border-white/[0.08] bg-[#141417] px-3 py-1 text-[11px] text-zinc-400">
            Built for Cloud &amp; DevOps Engineers · Guided Security Workflow
          </div>
          <h1 className="text-3xl font-semibold tracking-[-0.025em] text-white sm:text-4xl">
            Guided Vulnerability Scanning for Your Apps &amp; Infrastructure
          </h1>
          <p className="text-sm leading-relaxed text-zinc-400 sm:text-base">
            No security background required. Follow the 5-step dashboard guide to
            register targets, lock an authorized boundary, run isolated scanners, and
            prioritize fixes.
          </p>
          <div className="flex flex-wrap items-center gap-3 pt-2">
            <Link
              href="/login"
              className="vf-btn-primary h-9 rounded-full px-5 text-[13px]"
            >
              Get Started &amp; Sign In
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
            <Link
              href="/organizations"
              className="vf-btn-secondary h-9 rounded-full px-4 text-[13px]"
            >
              Open My Workspace
            </Link>
          </div>
        </section>

        <section className="overflow-hidden rounded-2xl border border-white/[0.068] bg-[#141417] shadow-[inset_0_1px_0_rgba(255,255,255,0.045)]">
          <div className="grid divide-y divide-white/[0.06] sm:grid-cols-3 sm:divide-x sm:divide-y-0">
            {STEPS.map((item) => {
              const Icon = item.icon;
              return (
                <div key={item.title} className="p-5 sm:p-6">
                  <div className="flex items-center justify-between text-zinc-500">
                    <Icon className="h-4 w-4 text-zinc-300" />
                    <span className="text-[11px] font-medium">{item.step}</span>
                  </div>
                  <h2 className="mt-4 text-sm font-semibold text-zinc-100">
                    {item.title}
                  </h2>
                  <p className="mt-1.5 text-xs leading-relaxed text-zinc-400">
                    {item.description}
                  </p>
                </div>
              );
            })}
          </div>
        </section>

        <section>
          <PlatformStatusCard />
        </section>
      </main>
    </div>
  );
}
