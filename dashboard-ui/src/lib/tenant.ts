import { optionalEnv, requiredEnv } from "@/lib/env";

export function resolveTenantId(searchParamsTenant?: string | string[]): string {
  if (Array.isArray(searchParamsTenant)) {
    if (searchParamsTenant[0]) return searchParamsTenant[0];
  } else if (searchParamsTenant) {
    return searchParamsTenant;
  }
  const fallback = optionalEnv("DASHBOARD_TENANT_ID");
  if (fallback) return fallback;
  return requiredEnv("DASHBOARD_TENANT_ID");
}
