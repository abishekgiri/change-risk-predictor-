"use client";

import { createRequestId } from "@/lib/request-id";

export async function callDashboardApi<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const requestId = createRequestId();
  const response = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      "X-Request-Id": requestId,
      ...(init.headers ?? {}),
    },
    cache: "no-store",
  });

  const text = await response.text();
  const payload = text ? JSON.parse(text) : {};
  const traceId = payload?.trace_id ?? response.headers.get("X-Request-Id");
  if (traceId) {
    // keep trace id visible during browser debugging
    // eslint-disable-next-line no-console
    console.debug(`[dashboard trace] ${traceId}`);
  }

  if (!response.ok) {
    const message = payload?.detail ?? payload?.error ?? `Request failed with status ${response.status}`;
    throw new Error(`${message} (trace_id=${traceId ?? "n/a"})`);
  }

  return payload as T;
}
