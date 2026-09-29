import type { ButtonHTMLAttributes, HTMLAttributes, ReactNode } from "react";
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]): string { return twMerge(clsx(inputs)); }

export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("border border-line bg-panel/90", className)} {...props} />;
}

export function Button({ className, ...props }: ButtonHTMLAttributes<HTMLButtonElement>) {
  return <button className={cn("border border-signal/40 bg-signal/10 px-3 py-2 font-mono text-[11px] uppercase tracking-[0.16em] text-signal transition hover:border-signal hover:bg-signal/15 disabled:cursor-not-allowed disabled:opacity-40", className)} {...props} />;
}

export function Badge({ children, tone = "neutral" }: { children: ReactNode; tone?: "good" | "warn" | "bad" | "neutral" }) {
  const tones = {
    good: "border-signal/40 bg-signal/10 text-signal",
    warn: "border-warning/40 bg-warning/10 text-warning",
    bad: "border-danger/40 bg-danger/10 text-danger",
    neutral: "border-line bg-white/[0.03] text-slate-300",
  };
  return <span className={cn("inline-flex border px-2 py-1 font-mono text-[10px] uppercase", tones[tone])}>{children}</span>;
}

export function SectionTitle({ eyebrow, title }: { eyebrow: string; title: string }) {
  return <div><p className="font-mono text-[10px] uppercase tracking-[0.28em] text-signal">{eyebrow}</p><h2 className="mt-2 text-xl font-semibold tracking-tight text-white">{title}</h2></div>;
}

export function Loading({ label = "Synchronising" }: { label?: string }) {
  return <div className="flex min-h-48 items-center justify-center border border-dashed border-line font-mono text-xs uppercase tracking-[0.2em] text-slate-500">{label}<span className="ml-2 animate-pulse text-signal">▮</span></div>;
}

export function ErrorState({ error }: { error: Error }) {
  return <div className="border border-danger/40 bg-danger/5 p-5 font-mono text-xs text-danger">API UNAVAILABLE // {error.message}</div>;
}
