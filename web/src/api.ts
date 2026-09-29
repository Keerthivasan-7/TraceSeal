const API_ROOT = "/api";

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_ROOT}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
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
