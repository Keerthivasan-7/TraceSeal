import type { ButtonHTMLAttributes, HTMLAttributes, ReactNode } from "react";
import { AlertTriangle } from "lucide-react";
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]): string { return twMerge(clsx(inputs)); }

export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("rounded-2xl border border-white/[0.07] bg-panel bg-glass-panel shadow-card", className)} {...props} />;
}

export function Button({ className, ...props }: ButtonHTMLAttributes<HTMLButtonElement>) {
  return <button className={cn("inline-flex items-center justify-center gap-1.5 rounded-full border border-signal/25 bg-signal/[0.09] px-4 py-2 font-mono text-[11px] font-medium uppercase tracking-[0.14em] text-signal transition hover:border-signal/50 hover:bg-signal/[0.16] hover:shadow-glow disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:border-signal/25 disabled:hover:bg-signal/[0.09] disabled:hover:shadow-none", className)} {...props} />;
}

export function Badge({ children, tone = "neutral" }: { children: ReactNode; tone?: "good" | "warn" | "bad" | "neutral" }) {
  const tones = {
    good: "border-signal/30 bg-signal/[0.1] text-signal",
    warn: "border-warning/30 bg-warning/[0.1] text-warning",
    bad: "border-danger/30 bg-danger/[0.1] text-danger",
    neutral: "border-white/[0.08] bg-white/[0.04] text-muted",
  };
  return <span className={cn("inline-flex items-center rounded-full border px-2.5 py-1 font-mono text-[10px] font-medium uppercase tracking-[0.06em]", tones[tone])}>{children}</span>;
}

export function SectionTitle({ eyebrow, title }: { eyebrow: string; title: string }) {
  return <div className="flex flex-col gap-2.5">
    <p className="flex items-center gap-2 font-mono text-[10px] font-medium uppercase tracking-[0.32em] text-signal"><span className="h-1.5 w-1.5 rounded-full bg-signal shadow-[0_0_10px_2px_rgb(var(--signal)/0.6)]" />{eyebrow}</p>
    <h2 className="text-[26px] font-semibold tracking-tight text-white">{title}</h2>
  </div>;
}

export function Loading({ label = "Synchronising" }: { label?: string }) {
  return <div className="flex min-h-48 flex-col items-center justify-center gap-3 rounded-2xl border border-dashed border-white/[0.08] bg-white/[0.015] font-mono text-[11px] uppercase tracking-[0.24em] text-muted">
    <div className="flex gap-1.5">
      <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-signal [animation-delay:-0.3s]" />
      <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-signal [animation-delay:-0.15s]" />
      <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-signal" />
    </div>
    {label}
  </div>;
}

export function BusyBar({ label, seconds }: { label: string; seconds: number }) {
  return <div className="space-y-2.5">
    <div className="flex items-center justify-between font-mono text-[10px] uppercase tracking-widest text-signal">
      <span>{label}</span>
      <span className="tabular-nums text-muted">{seconds}s elapsed</span>
    </div>
    <div className="h-1 w-full overflow-hidden rounded-full bg-white/[0.06]">
      <div className="h-full w-1/3 animate-indeterminate rounded-full bg-signal-gradient" />
    </div>
  </div>;
}

export function ErrorState({ error }: { error: Error }) {
  return <div className="flex items-start gap-3 rounded-2xl border border-danger/25 bg-danger/[0.06] p-5 font-mono text-xs leading-5 text-danger"><AlertTriangle size={15} className="mt-0.5 shrink-0" /><span>API unavailable — {error.message}</span></div>;
}
