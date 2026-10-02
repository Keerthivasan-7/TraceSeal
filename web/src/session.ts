import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import type { Screen } from "./store";

export type Role = "all" | "officer" | "command" | "authority" | "ops";

export interface SessionInfo {
  role: Role;
  identity_id: string | null;
  auth_required: boolean;
  authenticated: boolean;
  principal_ids: string[];
  cert_hash: string | null;
  idle_expires_in_s: number | null;
  abs_expires_in_s: number | null;
  allowed_screens: Screen[];
  container: string;
}

/** The host serves no console (plain localhost / 127.0.0.1): show the launcher. */
export class NoConsoleError extends Error {}

export class LoginError extends Error {
  constructor(
    message: string,
    readonly retryAfterSeconds: number | null,
  ) {
    super(message);
  }
}

export async function fetchSession(): Promise<SessionInfo> {
  // A passive read: asking "am I logged in?" must not itself keep a session alive.
  const response = await fetch("/api/session", { headers: { "X-TS-Passive": "1" } });
  if (response.status === 404) throw new NoConsoleError("no console on this host");
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return (await response.json()) as SessionInfo;
}

export function useSession() {
  return useQuery({
    queryKey: ["session"],
    queryFn: fetchSession,
    refetchInterval: 5_000,
    retry: (count, error) => !(error instanceof NoConsoleError) && count < 2,
  });
}

export async function login(passphrase: string): Promise<void> {
  const response = await fetch("/api/session/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ passphrase }),
  });
  if (response.ok) return;
  const body = (await response.json().catch(() => null)) as { detail?: string } | null;
  const retry = Number(response.headers.get("Retry-After"));
  throw new LoginError(
    body?.detail ?? `${response.status} ${response.statusText}`,
    Number.isFinite(retry) && retry > 0 ? retry : null,
  );
}

export async function logout(): Promise<void> {
  await fetch("/api/session/logout", { method: "POST" });
}

/** What this window should call itself: `officer-a`, `command`, `authority`, `ops`. */
export function consoleKey(info: SessionInfo): string {
  return info.identity_id ?? info.role;
}

export function consoleTitle(info: SessionInfo): string {
  switch (info.role) {
    case "officer":
      return `Officer workstation — ${info.identity_id}`;
    case "command":
      return "Command — document owner";
    case "authority":
      return "Enrolment authority";
    case "ops":
      return "Operations view";
    default:
      return "Combined console";
  }
}

/** Seconds left, counted down locally between the 5-second server polls. */
export function useCountdown(secondsAtFetch: number | null, fetchedAt: number): number | null {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1_000);
    return () => clearInterval(timer);
  }, []);
  if (secondsAtFetch === null) return null;
  return Math.max(0, Math.round(secondsAtFetch - (now - fetchedAt) / 1_000));
}

export function formatClock(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}:${String(s).padStart(2, "0")}`;
}
