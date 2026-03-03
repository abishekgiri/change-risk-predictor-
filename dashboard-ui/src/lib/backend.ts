import { createRequestId } from "@/lib/request-id";
import { requiredEnv } from "@/lib/env";

export async function backendFetch<T>(
  path: string,
  init: RequestInit & { query?: Record<string, string | number | boolean | undefined | null> } = {},
): Promise<{ data: T; traceId: string | null; status: number }> {
  const baseUrl = requiredEnv("DASHBOARD_API_BASE_URL");
  const token = requiredEnv("DASHBOARD_API_TOKEN");
  const query = init.query ?? {};
  const url = new URL(path, baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`);
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === "") continue;
    url.searchParams.set(key, String(value));
  }

  const requestId = createRequestId();
  const response = await fetch(url.toString(), {
    ...init,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      "X-Request-Id": requestId,
      ...(init.headers ?? {}),
    },
    cache: "no-store",
  });

  const text = await response.text();
  const payload = text ? JSON.parse(text) : {};
  const traceId = payload?.trace_id ?? response.headers.get("X-Request-Id");

  if (!response.ok) {
    const message = payload?.detail ?? payload?.error ?? `Backend request failed: ${response.status}`;
    throw new Error(`${message} (trace_id=${traceId ?? "n/a"})`);
  }

  return {
    data: payload as T,
    traceId: traceId ? String(traceId) : null,
    status: response.status,
  };
}
