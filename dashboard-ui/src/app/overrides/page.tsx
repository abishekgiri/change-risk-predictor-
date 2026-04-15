import { OverrideBreakdownTable } from "@/components/OverrideBreakdownTable";
import { TraceInfo } from "@/components/TraceInfo";
import { backendFetch } from "@/lib/backend";
import { resolveDashboardScope, scopeToQuery } from "@/lib/dashboard-scope";
import type { DashboardOverridesBreakdown, OverridesGroupBy } from "@/lib/types";

export const dynamic = "force-dynamic";

function normalizeGroupBy(value: string | string[] | undefined): OverridesGroupBy {
  const raw = Array.isArray(value) ? value[0] : value;
  const normalized = String(raw || "actor").trim().toLowerCase();
  if (normalized === "workflow" || normalized === "rule") {
    return normalized;
  }
  return "actor";
}

export default async function OverridesPage({
  searchParams,
}: {
  searchParams: Promise<{
    tenant_id?: string | string[];
    from?: string | string[];
    to?: string | string[];
    window_days?: string | string[];
    group_by?: string | string[];
  }>;
}) {
  const resolvedSearchParams = await searchParams;
  const scope = resolveDashboardScope(resolvedSearchParams);
  const baseQuery = scopeToQuery(scope);
  const groupBy = normalizeGroupBy(resolvedSearchParams.group_by);

  const breakdown = await backendFetch<DashboardOverridesBreakdown>("/dashboard/overrides/breakdown", {
    method: "GET",
    query: {
      ...baseQuery,
      group_by: groupBy,
      limit: 25,
    },
  });

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900">Override Breakdown</h1>
        </div>
      </div>
      <details className="text-xs text-slate-400">
        <summary className="cursor-pointer w-fit">Debug</summary>
        <div className="mt-1 space-y-0.5">
          <p className="text-sm text-slate-600">Tenant: {scope.tenantId}</p>
          <TraceInfo traceId={breakdown.data.trace_id ?? breakdown.traceId} />
        </div>
      </details>

      <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <form action="/overrides" method="get" className="flex flex-wrap items-end gap-3">
          <input type="hidden" name="tenant_id" value={scope.tenantId} />
          {scope.fromTs ? <input type="hidden" name="from" value={scope.fromTs} /> : null}
          {scope.toTs ? <input type="hidden" name="to" value={scope.toTs} /> : null}
          <label className="flex flex-col gap-1 text-sm font-medium text-slate-700">
            Group by
            <select
              name="group_by"
              defaultValue={groupBy}
              className="rounded-md border border-slate-300 px-3 py-2 text-sm text-slate-900 focus:border-slate-400 focus:outline-none"
            >
              <option value="actor">Actor</option>
              <option value="workflow">Workflow</option>
              <option value="rule">Rule</option>
            </select>
          </label>
          <button
            type="submit"
            className="rounded-md border border-slate-300 bg-slate-900 px-3 py-2 text-sm font-medium text-white hover:bg-slate-800"
          >
            Apply
          </button>
          <p className="ml-auto text-sm text-slate-500">Total overrides: {breakdown.data.total_overrides}</p>
        </form>
      </div>

      <OverrideBreakdownTable groupBy={groupBy} rows={breakdown.data.rows} />
    </div>
  );
}
