import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ChevronDown, ChevronUp, ShieldAlert } from "lucide-react";

import { api } from "../api";
import { cn } from "./ui";

interface SecurityEvent {
  at: string;
  kind: string;
  detail: string;
}

const BAD = new Set(["login_failed", "login_blocked", "scope_violation", "auth_invalid", "auth_missing"]);
const GOOD = new Set(["login_ok"]);

/** This console's own security log (logins, refusals, expiries) — never another console's. */
export function SecurityEvents() {
  const [open, setOpen] = useState(false);
  const events = useQuery({
    queryKey: ["security-events"],
    queryFn: () => api<SecurityEvent[]>("/security/events"),
    refetchInterval: 3_000,
  });
  const rows = events.data ?? [];
  const alerts = rows.filter((e) => BAD.has(e.kind)).length;

  return (
    <div className="fixed bottom-4 right-4 z-20 w-[22rem] max-w-[calc(100vw-2rem)] font-mono text-[10px]">
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center justify-between rounded-t-xl border border-white/[0.08] bg-[#070a08]/95 px-3 py-2 uppercase tracking-widest text-muted backdrop-blur-xl"
      >
        <span className="flex items-center gap-2">
          <ShieldAlert size={13} className={alerts ? "text-danger" : "text-signal"} />
          Security events
          {alerts > 0 && <span className="rounded-full bg-danger/20 px-2 text-danger">{alerts}</span>}
        </span>
        {open ? <ChevronDown size={13} /> : <ChevronUp size={13} />}
      </button>
      {open && (
        <div className="max-h-64 overflow-y-auto rounded-b-xl border border-t-0 border-white/[0.08] bg-[#070a08]/95 backdrop-blur-xl">
          {rows.length === 0 && <div className="p-4 text-center uppercase tracking-widest text-muted">Nothing yet</div>}
          {rows.slice(0, 40).map((e, i) => (
            <div key={`${e.at}-${i}`} className="border-b border-white/[0.04] px-3 py-2 last:border-0">
              <div className="flex items-center justify-between gap-2">
                <span
                  className={cn(
                    "uppercase tracking-widest",
                    BAD.has(e.kind) ? "text-danger" : GOOD.has(e.kind) ? "text-signal" : "text-slate-300",
                  )}
                >
                  {e.kind.replaceAll("_", " ")}
                </span>
                <span className="text-muted">{e.at.slice(11, 19)}</span>
              </div>
              <div className="mt-0.5 leading-4 text-muted">{e.detail}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
