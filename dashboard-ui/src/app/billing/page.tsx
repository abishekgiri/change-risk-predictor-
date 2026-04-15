import { KpiCard } from "@/components/KpiCard";
import { TraceInfo } from "@/components/TraceInfo";
import { backendFetch } from "@/lib/backend";
import { resolveDashboardScope } from "@/lib/dashboard-scope";
import type { BillingUsage } from "@/lib/types";

export const dynamic = "force-dynamic";

function renderLimit(value: number | null, suffix = ""): string {
  if (value === null) return "Unlimited";
  return `${value}${suffix}`;
}

function renderUsagePercent(value: number | null): string {
  if (value === null) return "N/A";
  return `${value.toFixed(2)}%`;
}

export default async function BillingPage({
  searchParams,
}: {
  searchParams: Promise<{
    tenant_id?: string | string[];
  }>;
}) {
  const resolvedSearchParams = await searchParams;
  const scope = resolveDashboardScope(resolvedSearchParams);

  const usage = await backendFetch<BillingUsage>("/dashboard/billing/usage", {
    method: "GET",
    query: { tenant_id: scope.tenantId },
  });

  const payload = usage.data;

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900">Billing & Quotas</h1>
          <p className="mt-1 text-sm text-slate-600">
            Plan: <span className="font-medium text-slate-900">{payload.plan}</span>
          </p>
        </div>
      </div>
      <details className="text-xs text-slate-400">
        <summary className="cursor-pointer w-fit">Debug</summary>
        <div className="mt-1 space-y-0.5">
          <p className="text-sm text-slate-600">Tenant: {payload.tenant_id}</p>
          <TraceInfo traceId={payload.trace_id ?? usage.traceId} />
        </div>
      </details>

      <section className="grid gap-4 md:grid-cols-3">
        <KpiCard
          label="Decision Volume"
          value={`${payload.decisions_this_month}`}
          helper={`${renderLimit(payload.decision_limit)} monthly • ${renderUsagePercent(payload.decision_usage_pct)} used`}
        />
        <KpiCard
          label="Override Volume"
          value={`${payload.overrides_this_month}`}
          helper={`${renderLimit(payload.override_limit)} monthly • ${renderUsagePercent(payload.override_usage_pct)} used`}
        />
        <KpiCard
          label="Storage"
          value={`${payload.storage_mb.toFixed(2)} MB`}
          helper={`${renderLimit(payload.storage_limit_mb, " MB")} • ${renderUsagePercent(payload.storage_usage_pct)} used`}
        />
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <h2 className="text-lg font-semibold text-slate-900">Quota Breakdown</h2>
        <div className="mt-3 overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
                <th className="py-2 pr-3">Metric</th>
                <th className="py-2 pr-3">Usage</th>
                <th className="py-2 pr-3">Limit</th>
                <th className="py-2">Utilization</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-slate-100">
                <td className="py-2 pr-3 text-slate-700">Decisions (month)</td>
                <td className="py-2 pr-3 text-slate-700">{payload.decisions_this_month}</td>
                <td className="py-2 pr-3 text-slate-700">{renderLimit(payload.decision_limit)}</td>
                <td className="py-2 text-slate-700">{renderUsagePercent(payload.decision_usage_pct)}</td>
              </tr>
              <tr className="border-b border-slate-100">
                <td className="py-2 pr-3 text-slate-700">Overrides (month)</td>
                <td className="py-2 pr-3 text-slate-700">{payload.overrides_this_month}</td>
                <td className="py-2 pr-3 text-slate-700">{renderLimit(payload.override_limit)}</td>
                <td className="py-2 text-slate-700">{renderUsagePercent(payload.override_usage_pct)}</td>
              </tr>
              <tr className="border-b border-slate-100">
                <td className="py-2 pr-3 text-slate-700">Storage</td>
                <td className="py-2 pr-3 text-slate-700">{payload.storage_mb.toFixed(2)} MB</td>
                <td className="py-2 pr-3 text-slate-700">{renderLimit(payload.storage_limit_mb, " MB")}</td>
                <td className="py-2 text-slate-700">{renderUsagePercent(payload.storage_usage_pct)}</td>
              </tr>
              <tr>
                <td className="py-2 pr-3 text-slate-700">Simulation Runs</td>
                <td className="py-2 pr-3 text-slate-700">{payload.simulation_runs}</td>
                <td className="py-2 pr-3 text-slate-700">{payload.simulation_history_days_limit} day lookback</td>
                <td className="py-2 text-slate-700">N/A</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
