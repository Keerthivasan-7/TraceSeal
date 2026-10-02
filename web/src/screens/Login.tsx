import { useEffect, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { KeyRound } from "lucide-react";

import { Logo } from "../components/Logo";
import { Button, Card } from "../components/ui";
import { consoleTitle, login, LoginError, type SessionInfo } from "../session";

export function Login({ session }: { session: SessionInfo }) {
  const queryClient = useQueryClient();
  const [passphrase, setPassphrase] = useState("");
  const [blockedUntil, setBlockedUntil] = useState<number | null>(null);
  const [now, setNow] = useState(() => Date.now());

  const attempt = useMutation({
    mutationFn: () => login(passphrase),
    onSuccess: async () => {
      setPassphrase("");
      await queryClient.invalidateQueries();
    },
    onError: (error) => {
      setPassphrase("");
      if (error instanceof LoginError && error.retryAfterSeconds) {
        setBlockedUntil(Date.now() + error.retryAfterSeconds * 1_000);
      }
    },
  });

  useEffect(() => {
    if (blockedUntil === null) return;
    const timer = setInterval(() => setNow(Date.now()), 500);
    return () => clearInterval(timer);
  }, [blockedUntil]);

  const waitSeconds = blockedUntil === null ? 0 : Math.max(0, Math.ceil((blockedUntil - now) / 1_000));
  const blocked = waitSeconds > 0;

  return (
    <div className="mx-auto flex min-h-screen max-w-md flex-col justify-center gap-6 p-6">
      <div className="flex items-center gap-4">
        <div className="grid h-12 w-12 place-items-center rounded-2xl border border-signal/30 bg-signal-gradient text-ink shadow-glow">
          <Logo size={24} />
        </div>
        <div>
          <div className="font-mono text-[15px] font-semibold tracking-[0.24em] text-white">TRACESEAL</div>
          <div className="mt-1 font-mono text-[10px] uppercase tracking-[0.2em] text-signal">{consoleTitle(session)}</div>
        </div>
      </div>

      <Card className="p-6">
        <form
          onSubmit={(event) => {
            event.preventDefault();
            if (passphrase && !blocked) attempt.mutate();
          }}
          className="space-y-4"
        >
          <label className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-widest text-slate-400">
            <KeyRound size={13} className="text-signal" /> Unlock keystore
          </label>
          <input
            autoFocus
            type="password"
            autoComplete="off"
            spellCheck={false}
            value={passphrase}
            onChange={(event) => setPassphrase(event.target.value)}
            placeholder="Keystore passphrase"
            className="w-full border border-line bg-black/30 px-3 py-2 font-mono text-xs text-white outline-none focus:border-signal/40"
          />
          <Button type="submit" disabled={!passphrase || attempt.isPending || blocked} className="w-full">
            {attempt.isPending ? "Deriving key…" : blocked ? `Locked — retry in ${waitSeconds}s` : "Unlock"}
          </Button>
          {attempt.error && (
            <div className="font-mono text-[11px] leading-5 text-danger">{(attempt.error as Error).message}</div>
          )}
        </form>
      </Card>

      <p className="font-mono text-[10px] leading-5 text-muted">
        The passphrase decrypts this workstation&apos;s Argon2id-protected keystore inside the container{" "}
        <span className="text-slate-300">{session.container}</span>. It is never stored by the browser, and
        no other console&apos;s passphrase will work here.
      </p>
    </div>
  );
}
