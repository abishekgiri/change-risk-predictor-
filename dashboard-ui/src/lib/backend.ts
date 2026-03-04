import { createRequestId } from "@/lib/request-id";
import { optionalEnv, requiredEnv } from "@/lib/env";

function looksLikeJwt(token: string): boolean {
  return token.trim().split(".").length === 3;
}

function internalServiceHeaders(token: string): Record<string, string> {
  const headers: Record<string, string> = { "X-Internal-Service-Key": token };
  const tenantId = optionalEnv("DASHBOARD_TENANT_ID");
  if (tenantId) {
    headers["X-Tenant-Id"] = tenantId;
  }
  return headers;
}

function resolveAuthHeaderCandidates(token: string): Array<Record<string, string>> {
  const mode = optionalEnv("DASHBOARD_API_AUTH_MODE", "auto").toLowerCase();
  if (mode === "bearer") {
    return [{ Authorization: `Bearer ${token}` }];
  }
  if (mode === "api_key") {
    return [{ "X-API-Key": token }];
  }
  if (mode === "internal_service") {
    return [internalServiceHeaders(token)];
  }
  if (looksLikeJwt(token)) {
    return [{ Authorization: `Bearer ${token}` }];
  }
  if (token.startsWith("rgk_")) {
    return [{ "X-API-Key": token }, internalServiceHeaders(token)];
  }
  return [internalServiceHeaders(token), { "X-API-Key": token }];
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
  const authHeaderCandidates = resolveAuthHeaderCandidates(token);
  const retryableAuthCodes = new Set([
    "AUTH_API_KEY_INVALID",
    "AUTH_INTERNAL_SERVICE_INVALID",
    "AUTH_INTERNAL_SERVICE_FORBIDDEN",
    "AUTH_REQUIRED",
  ]);

  let lastError: Error | null = null;
  for (let index = 0; index < authHeaderCandidates.length; index += 1) {
    const authHeaders = authHeaderCandidates[index];
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
    const errorObj =
      payloadObj.error && typeof payloadObj.error === "object" ? (payloadObj.error as Record<string, unknown>) : {};
    const traceId =
      payloadObj.trace_id ??
      errorObj.request_id ??
      response.headers.get("X-Request-Id");

    if (response.ok) {
      let responsePayload = payload as T;
      if (
        payloadObj &&
        Object.prototype.hasOwnProperty.call(payloadObj, "data") &&
        payloadObj.data &&
        typeof payloadObj.data === "object"
      ) {
        responsePayload = payloadObj.data as T;
        if (responsePayload && typeof responsePayload === "object") {
          const normalizedPayload = responsePayload as unknown as Record<string, unknown>;
          if (!("trace_id" in normalizedPayload) && traceId) {
            normalizedPayload.trace_id = String(traceId);
          }
          if (!("generated_at" in normalizedPayload) && typeof payloadObj.generated_at === "string") {
            normalizedPayload.generated_at = payloadObj.generated_at;
          }
        }
      }
      return {
        data: responsePayload,
        traceId: traceId ? String(traceId) : null,
        status: response.status,
      };
    }

    const detail = payloadObj?.detail;
    const detailObj = detail && typeof detail === "object" ? (detail as Record<string, unknown>) : {};
    const errorCode =
      (typeof detailObj.error_code === "string" && detailObj.error_code) ||
      (typeof errorObj.error_code === "string" && errorObj.error_code) ||
      (typeof errorObj.code === "string" && errorObj.code) ||
      "";
    const shouldRetryAuthHeader =
      response.status === 401 && retryableAuthCodes.has(errorCode) && index < authHeaderCandidates.length - 1;
    if (shouldRetryAuthHeader) {
      continue;
    }

    const message = extractErrorMessage(payload, response.status);
    lastError = new Error(
      `HTTP ${response.status}: ${message} (trace_id=${traceId ?? "n/a"}, url=${url.toString()})`,
    );
    break;
  }

  if (lastError) {
    throw lastError;
  }
  throw new Error("Backend request failed before authentication could be attempted");
}
