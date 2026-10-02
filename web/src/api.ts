const API_ROOT = "/api";

// Called when any request is rejected as not-logged-in (expired/revoked
// session), so the app can fall back to the login screen at once.
let onUnauthorized: (() => void) | null = null;
export function setUnauthorizedHandler(handler: (() => void) | null): void {
  onUnauthorized = handler;
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  // Plain GETs are background reads (polling, list refreshes): mark them
  // passive so they don't reset the server's idle timeout. Anything a person
  // does on purpose (POST/PUT/DELETE, loading a page image) counts as activity.
  const passive = !init?.method || init.method.toUpperCase() === "GET";
  const response = await fetch(`${API_ROOT}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(passive ? { "X-TS-Passive": "1" } : {}),
      ...init?.headers,
    },
  });
  if (response.status === 401) onUnauthorized?.();
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as { detail?: string } | null;
    throw new Error(body?.detail ?? `${response.status} ${response.statusText}`);
  }
  return (await response.json()) as T;
}

export async function apiUpload<T>(path: string, formData: FormData): Promise<T> {
  const response = await fetch(`${API_ROOT}${path}`, { method: "POST", body: formData });
  if (response.status === 401) onUnauthorized?.();
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as { detail?: string } | null;
    throw new Error(body?.detail ?? `${response.status} ${response.statusText}`);
  }
  return (await response.json()) as T;
}

export function compactId(value: string, visible = 10): string {
  return value.length <= visible * 2 + 1
    ? value
    : `${value.slice(0, visible)}…${value.slice(-visible)}`;
}

export function domainLabel(domain: string): string {
  return domain.replace(/^traceseal\//, "").replace(/\/v\d+$/, "").replaceAll("-", " ");
}

export function payloadString(payload: Record<string, unknown> | null, key: string): string | null {
  const value = payload?.[key];
  return typeof value === "string" ? value : null;
}
