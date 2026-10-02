import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Lock, ShieldCheck } from "lucide-react";

import { compactId } from "../api";
import { Badge, Button } from "./ui";
import { consoleTitle, formatClock, logout, useCountdown, type SessionInfo } from "../session";

/** Always-visible statement of who this window is and where its keys live. */
export function IdentityBar({ info, fetchedAt }: { info: SessionInfo; fetchedAt: number }) {
  const queryClient = useQueryClient();
  const lock = useMutation({
    mutationFn: logout,
    onSuccess: () => queryClient.invalidateQueries(),
  });
  const idle = useCountdown(info.idle_expires_in_s, fetchedAt);
  const absolute = useCountdown(info.abs_expires_in_s, fetchedAt);

  if (info.role === "all") return null;

  const readOnly = !info.auth_required;
  return (
    <div className="sticky top-0 z-10 flex flex-wrap items-center gap-x-5 gap-y-2 border-b border-white/[0.06] bg-[#070a08]/90 px-5 py-2.5 font-mono text-[10px] uppercase tracking-widest backdrop-blur-xl md:px-8">
      <span className="flex items-center gap-2 text-signal">
        <ShieldCheck size={14} />
        {consoleTitle(info)}
      </span>

      {readOnly ? (
        <span className="text-muted">read-only view // holds no private keys</span>
      ) : (
        <>
          <span className="text-muted">
            keys live in container <span className="text-slate-200">{info.container}</span>
          </span>
          {info.cert_hash && (
            <span className="text-muted">
              cert <span className="text-slate-200">{compactId(info.cert_hash, 8)}</span>
            </span>
          )}
          {info.principal_ids.length > 1 && (
            <span className="text-muted">
              unlocked: <span className="text-slate-200">{info.principal_ids.join(", ")}</span>
            </span>
          )}
          <span className="ml-auto flex items-center gap-3">
            {idle !== null && (
              <Badge tone={idle < 60 ? "warn" : "neutral"}>auto-lock in {formatClock(idle)}</Badge>
            )}
            {absolute !== null && absolute < 300 && <Badge tone="warn">session ends {formatClock(absolute)}</Badge>}
            <Button disabled={lock.isPending} onClick={() => lock.mutate()}>
              <Lock size={12} /> Lock
            </Button>
          </span>
        </>
      )}
    </div>
  );
}
