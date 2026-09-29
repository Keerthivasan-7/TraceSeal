import { Activity, Fingerprint, Network, ShieldCheck } from "lucide-react";

import { useConsoleStore, type Screen } from "../store";
import { cn } from "./ui";

const nav: Array<{ id: Screen; label: string; icon: typeof Activity }> = [
  { id: "command", label: "Command Center", icon: Activity },
  { id: "identity", label: "Identity", icon: Fingerprint },
  { id: "ledger", label: "Ledger", icon: Network },
];

export function Shell({ children }: { children: React.ReactNode }) {
  const { screen, setScreen } = useConsoleStore();
  return <div className="min-h-screen bg-ink text-slate-200">
    <div className="fixed inset-x-0 top-0 z-20 h-[2px] bg-gradient-to-r from-transparent via-signal to-transparent opacity-70" />
    <aside className="fixed inset-y-0 left-0 hidden w-64 border-r border-line bg-[#090c0f] lg:block">
      <div className="border-b border-line p-6"><div className="flex items-center gap-3"><div className="grid h-10 w-10 place-items-center border border-signal/50 bg-signal/10 text-signal shadow-signal"><ShieldCheck size={20} /></div><div><div className="font-mono text-sm font-semibold tracking-[0.22em] text-white">TRACESEAL</div><div className="mt-1 font-mono text-[9px] uppercase tracking-[0.18em] text-slate-500">Air-gapped console</div></div></div></div>
      <nav className="p-3">{nav.map(({ id, label, icon: Icon }) => <button key={id} onClick={() => setScreen(id)} className={cn("mb-1 flex w-full items-center gap-3 border border-transparent px-3 py-3 text-left font-mono text-[11px] uppercase tracking-[0.12em] transition", screen === id ? "border-signal/30 bg-signal/[0.07] text-signal" : "text-slate-500 hover:bg-white/[0.03] hover:text-slate-200")}><Icon size={15} /> {label}</button>)}</nav>
      <div className="absolute inset-x-5 bottom-5 border border-line bg-black/20 p-3 font-mono text-[9px] uppercase leading-5 tracking-wider text-slate-600"><span className="mr-2 inline-block h-1.5 w-1.5 rounded-full bg-signal shadow-[0_0_8px_#64f4ac]" />local control plane<br />cloud dependencies: none</div>
    </aside>
    <header className="border-b border-line bg-[#090c0f] p-3 lg:hidden"><div className="mb-3 font-mono text-sm tracking-[0.2em] text-white">TRACESEAL</div><div className="flex gap-2 overflow-x-auto">{nav.map(({ id, label }) => <button key={id} onClick={() => setScreen(id)} className={cn("whitespace-nowrap border px-3 py-2 font-mono text-[10px] uppercase", screen === id ? "border-signal/40 text-signal" : "border-line text-slate-500")}>{label}</button>)}</div></header>
    <main className="lg:pl-64">{children}</main>
  </div>;
}
