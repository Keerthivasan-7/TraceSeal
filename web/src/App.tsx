import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";

import { setUnauthorizedHandler } from "./api";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { Shell } from "./components/Shell";
import { ErrorState, Loading } from "./components/ui";
import { AttackLab } from "./screens/AttackLab";
import { CommandCenter } from "./screens/CommandCenter";
import { Distribute } from "./screens/Distribute";
import { Identity } from "./screens/Identity";
import { Inbox } from "./screens/Inbox";
import { Investigate } from "./screens/Investigate";
import { Landing } from "./screens/Landing";
import { Ledger } from "./screens/Ledger";
import { Login } from "./screens/Login";
import { Monitor } from "./screens/Monitor";
import { consoleKey, NoConsoleError, useSession, type SessionInfo } from "./session";
import { useConsoleStore, type Screen } from "./store";

// Every screen stays mounted for the lifetime of the app once first shown —
// only visually hidden when inactive, never unmounted — so that a
// long-running operation started on one screen (a document upload, an
// investigation pipeline run, a decrypt session) keeps its state and
// eventually shows its result even if the operator switches to another
// screen and back. Unmounting on navigation (the previous approach) tore
// down each screen's mutation state instantly, silently discarding the
// outcome of any request still in flight when the operator navigated away —
// the actual HTTP request kept running on the server, but nothing on the
// client was left to receive or display the result.
const screens: Array<{ id: Screen; label: string; render: () => JSX.Element }> = [
  { id: "command", label: "Command Center", render: () => <CommandCenter /> },
  { id: "identity", label: "Identity", render: () => <Identity /> },
  { id: "distribute", label: "Distribute", render: () => <Distribute /> },
  { id: "inbox", label: "Officer Inbox", render: () => <Inbox /> },
  { id: "monitor", label: "Monitor", render: () => <Monitor /> },
  { id: "investigate", label: "Investigate", render: () => <Investigate /> },
  { id: "ledger", label: "Ledger", render: () => <Ledger /> },
  { id: "attacklab", label: "Attack Lab", render: () => <AttackLab /> },
];

function Console({ info, fetchedAt }: { info: SessionInfo; fetchedAt: number }) {
  const screen = useConsoleStore((state) => state.screen);
  const setScreen = useConsoleStore((state) => state.setScreen);
  const allowed = info.allowed_screens;
  // A role only ever sees its own screens; land on the first one it has.
  useEffect(() => {
    const first = allowed[0];
    if (first && !allowed.includes(screen)) setScreen(first);
  }, [allowed, screen, setScreen]);

  const [visited, setVisited] = useState<Set<Screen>>(() => new Set([screen]));
  if (!visited.has(screen)) {
    setVisited(new Set(visited).add(screen));
  }
  return <Shell info={info} fetchedAt={fetchedAt} allowed={allowed}>
    {screens
      .filter(({ id }) => allowed.includes(id) && visited.has(id))
      .map(({ id, label, render }) => (
        <div key={id} className={id === screen ? "" : "hidden"}>
          <ErrorBoundary label={label}>{render()}</ErrorBoundary>
        </div>
      ))}
  </Shell>;
}

export function App() {
  const queryClient = useQueryClient();
  const session = useSession();
  const info = session.data;

  // Any request rejected as "not logged in" (idle/absolute expiry, logout in
  // another tab) sends the window straight back to the login screen.
  useEffect(() => {
    setUnauthorizedHandler(() => void queryClient.invalidateQueries({ queryKey: ["session"] }));
    return () => setUnauthorizedHandler(null);
  }, [queryClient]);

  // Name the window after who it is: a per-console accent and tab title.
  useEffect(() => {
    if (!info) return;
    document.documentElement.dataset.role = consoleKey(info);
    document.title = `TraceSeal — ${consoleKey(info)}`;
  }, [info]);

  // Locked or expired: drop everything fetched under that login (document
  // lists, decrypted-page metadata) rather than leaving it in the query cache.
  const locked = !!info && info.auth_required && !info.authenticated;
  useEffect(() => {
    if (locked) queryClient.removeQueries({ predicate: (q) => q.queryKey[0] !== "session" });
  }, [locked, queryClient]);

  if (session.isLoading) return <Loading label="Connecting" />;
  if (session.error instanceof NoConsoleError) return <Landing />;
  if (!info) return <ErrorState error={session.error ?? new Error("no session")} />;
  if (locked) return <Login session={info} />;
  return <Console info={info} fetchedAt={session.dataUpdatedAt} />;
}
