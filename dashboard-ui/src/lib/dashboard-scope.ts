import { resolveTenantId } from "@/lib/tenant";

export type DashboardRangePreset = "default" | "last_24h" | "last_7d" | "last_30d";

const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_WINDOW_DAYS = 90;
const DEFAULT_WINDOW_DAYS = 30;

type SearchParamValue = string | string[] | undefined;

export interface DashboardScope {
  tenantId: string;
  fromTs: string | null;
  toTs: string | null;
  windowDays: number;
}

function firstValue(value: SearchParamValue): string | null {
  if (Array.isArray(value)) {
    const first = value.find((item) => item && item.trim().length > 0);
    return first?.trim() || null;
  }
  if (typeof value === "string" && value.trim().length > 0) {
    return value.trim();
  }
  return null;
}

function parseIso(value: string | null): Date | null {
  if (!value) return null;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed;
}

function boundedWindowDays(value: number): number {
  if (!Number.isFinite(value)) return DEFAULT_WINDOW_DAYS;
  const rounded = Math.ceil(value);
  if (rounded < 1) return 1;
  if (rounded > MAX_WINDOW_DAYS) return MAX_WINDOW_DAYS;
  return rounded;
}

export function resolveDashboardScope(searchParams: {
  tenant_id?: SearchParamValue;
  from?: SearchParamValue;
  to?: SearchParamValue;
  window_days?: SearchParamValue;
}): DashboardScope {
  const tenantId = resolveTenantId(searchParams.tenant_id);
  const fromTs = firstValue(searchParams.from);
  const toTs = firstValue(searchParams.to);
  const fromDate = parseIso(fromTs);
  const toDate = parseIso(toTs);

  let windowDays = DEFAULT_WINDOW_DAYS;
  if (fromDate && toDate && toDate.getTime() >= fromDate.getTime()) {
    windowDays = boundedWindowDays((toDate.getTime() - fromDate.getTime()) / DAY_MS);
  } else {
    const explicitWindowRaw = firstValue(searchParams.window_days);
    const explicitWindow = explicitWindowRaw ? Number(explicitWindowRaw) : DEFAULT_WINDOW_DAYS;
    windowDays = boundedWindowDays(explicitWindow);
  }

  return {
    tenantId,
    fromTs: fromDate ? fromDate.toISOString() : null,
    toTs: toDate ? toDate.toISOString() : null,
    windowDays,
  };
}

export function scopeToQuery(scope: DashboardScope): Record<string, string | number> {
  const query: Record<string, string | number> = {
    tenant_id: scope.tenantId,
    window_days: scope.windowDays,
  };
  if (scope.fromTs) query.from = scope.fromTs;
  if (scope.toTs) query.to = scope.toTs;
  return query;
}

export function scopeParamsFromSearch(searchParams: URLSearchParams): URLSearchParams {
  const params = new URLSearchParams();
  const tenantId = searchParams.get("tenant_id");
  const fromTs = searchParams.get("from");
  const toTs = searchParams.get("to");
  if (tenantId) params.set("tenant_id", tenantId);
  if (fromTs) params.set("from", fromTs);
  if (toTs) params.set("to", toTs);
  return params;
}

export function presetWindow(preset: Exclude<DashboardRangePreset, "default">): { fromTs: string; toTs: string } {
  const now = new Date();
  const end = new Date(now.getTime());
  const start = new Date(now.getTime());
  if (preset === "last_24h") {
    start.setHours(start.getHours() - 24);
  } else if (preset === "last_7d") {
    start.setDate(start.getDate() - 7);
  } else {
    start.setDate(start.getDate() - 30);
  }
  return { fromTs: start.toISOString(), toTs: end.toISOString() };
}

export function inferRangePreset(fromTs: string | null, toTs: string | null): DashboardRangePreset {
  const fromDate = parseIso(fromTs);
  const toDate = parseIso(toTs);
  if (!fromDate || !toDate || toDate.getTime() <= fromDate.getTime()) {
    return "default";
  }
  const diffHours = (toDate.getTime() - fromDate.getTime()) / (60 * 60 * 1000);
  if (Math.abs(diffHours - 24) <= 1) return "last_24h";
  if (Math.abs(diffHours - 168) <= 4) return "last_7d";
  if (Math.abs(diffHours - 720) <= 8) return "last_30d";
  return "default";
}
