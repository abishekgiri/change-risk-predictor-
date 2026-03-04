import { createRequestId } from "@/lib/request-id";
import { optionalEnv, requiredEnv } from "@/lib/env";

function looksLikeJwt(token: string): boolean {
  return token.trim().split(".").length === 3;
}

function resolveAuthHeaders(token: string): Record<string, string> {
  const mode = optionalEnv("DASHBOARD_API_AUTH_MODE", "auto").toLowerCase();
  if (mode === "bearer") {
    return { Authorization: `Bearer ${token}` };
  }
  if (mode === "api_key") {
    return { "X-API-Key": token };
  }
  return looksLikeJwt(token) ? { Authorization: `Bearer ${token}` } : { "X-API-Key": token };
}

function extractErrorMessage(payload: unknown, status: number): string {
  if (typeof payload === "string" && payload.trim()) {
    return payload;
  }

  if (payload && typeof payload === "object") {
    const data = payload as Record<string, unknown>;
    const detail = data.detail;
    if (typeof detail === "string" && detail.trim()) {
      return detail;
    }
    if (detail && typeof detail === "object") {
      const detailObj = detail as Record<string, unknown>;
      if (typeof detailObj.message === "string" && detailObj.message.trim()) {
        return detailObj.message;
      }
      return JSON.stringify(detailObj);
    }

    const error = data.error;
    if (typeof error === "string" && error.trim()) {
      return error;
    }
    if (error && typeof error === "object") {
      const errorObj = error as Record<string, unknown>;
      if (typeof errorObj.message === "string" && errorObj.message.trim()) {
        return errorObj.message;
      }
      return JSON.stringify(errorObj);
    }

    return JSON.stringify(data);
  }

  return `Backend request failed: ${status}`;
}

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
  const authHeaders = resolveAuthHeaders(token);
  const response = await fetch(url.toString(), {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...authHeaders,
      "X-Request-Id": requestId,
      ...(init.headers ?? {}),
    },
    cache: "no-store",
  });

  const text = await response.text();
  let payload: unknown = {};
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = text;
    }
  }

  const payloadObj = payload && typeof payload === "object" ? (payload as Record<string, unknown>) : {};
  const traceId = payloadObj.trace_id ?? response.headers.get("X-Request-Id");

  if (!response.ok) {
    const message = extractErrorMessage(payload, response.status);
    throw new Error(`HTTP ${response.status}: ${message} (trace_id=${traceId ?? "n/a"})`);
  }

  return {
    data: payload as T,
    traceId: traceId ? String(traceId) : null,
    status: response.status,
  };
}
