import {
  Activity,
  Fingerprint,
  FlaskConical,
  Inbox as InboxIcon,
  Network,
  Radar,
  Send,
  ShieldCheck,
  Telescope,
} from "lucide-react";

import { useConsoleStore, type Screen } from "../store";
import { cn } from "./ui";

const nav: Array<{ id: Screen; label: string; icon: typeof Activity }> = [
  { id: "command", label: "Command Center", icon: Activity },
  { id: "identity", label: "Identity", icon: Fingerprint },
  { id: "distribute", label: "Distribute", icon: Send },
  { id: "inbox", label: "Officer Inbox", icon: InboxIcon },
  { id: "monitor", label: "Monitor", icon: Radar },
  { id: "investigate", label: "Investigate", icon: Telescope },
  { id: "ledger", label: "Ledger", icon: Network },
  { id: "attacklab", label: "Attack Lab", icon: FlaskConical },
];

export function Shell({ children }: { children: React.ReactNode }) {
  const { screen, setScreen } = useConsoleStore();
  return <div className="min-h-screen bg-ink font-sans text-slate-200">
    <div className="fixed inset-x-0 top-0 z-20 h-px bg-gradient-to-r from-transparent via-signal/70 to-transparent" />
    <aside className="fixed inset-y-0 left-0 hidden w-[272px] border-r border-white/[0.06] bg-[#070a08]/95 backdrop-blur-xl lg:flex lg:flex-col">
      <div className="border-b border-white/[0.06] p-6">
        <div className="flex items-center gap-3">
          <div className="relative grid h-11 w-11 shrink-0 place-items-center rounded-2xl border border-signal/30 bg-signal-gradient text-ink shadow-glow">
            <ShieldCheck size={20} strokeWidth={2.25} />
          </div>
          <div>
            <div className="font-mono text-[13px] font-semibold tracking-[0.24em] text-white">TRACESEAL</div>
            <div className="mt-1 font-mono text-[9px] uppercase tracking-[0.2em] text-muted">Air-gapped console</div>
          </div>
        </div>
      </div>
      <nav className="flex-1 space-y-1 overflow-y-auto p-3">
        {nav.map(({ id, label, icon: Icon }) => {
          const active = screen === id;
          return <button key={id} onClick={() => setScreen(id)} className={cn("group flex w-full items-center gap-3 rounded-xl px-3.5 py-2.5 text-left font-mono text-[11px] font-medium uppercase tracking-[0.1em] transition-all duration-150", active ? "bg-signal/[0.1] text-signal shadow-[inset_0_0_0_1px_rgba(63,232,163,0.28)]" : "text-muted hover:bg-white/[0.04] hover:text-slate-200")}>
            <Icon size={16} strokeWidth={2} className={cn("shrink-0 transition-colors", active ? "text-signal" : "text-muted group-hover:text-slate-300")} />
            {label}
          </button>;
        })}
      </nav>
      <div className="m-4 rounded-2xl border border-white/[0.07] bg-white/[0.025] p-4 font-mono text-[9px] uppercase leading-6 tracking-wider text-muted">
        <span className="mr-2 inline-block h-1.5 w-1.5 rounded-full bg-signal shadow-[0_0_10px_2px_rgba(63,232,163,0.55)]" />
        local control plane<br />cloud dependencies: none
      </div>
    </aside>
    <header className="border-b border-white/[0.06] bg-[#070a08]/95 p-4 backdrop-blur-xl lg:hidden">
      <div className="mb-3 flex items-center gap-2.5">
        <div className="grid h-8 w-8 place-items-center rounded-xl border border-signal/30 bg-signal-gradient text-ink"><ShieldCheck size={15} /></div>
        <span className="font-mono text-[13px] font-semibold tracking-[0.2em] text-white">TRACESEAL</span>
      </div>
      <div className="flex gap-2 overflow-x-auto pb-1">{nav.map(({ id, label }) => <button key={id} onClick={() => setScreen(id)} className={cn("whitespace-nowrap rounded-full border px-3.5 py-1.5 font-mono text-[10px] font-medium uppercase tracking-[0.08em] transition", screen === id ? "border-signal/40 bg-signal/[0.1] text-signal" : "border-white/[0.08] text-muted")}>{label}</button>)}</div>
    </header>
    <main className="lg:pl-[272px]">{children}</main>
  </div>;
}
