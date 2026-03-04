import { AlertsList } from "@/components/AlertsList";
import { KpiCard } from "@/components/KpiCard";
import { LineChartCard } from "@/components/LineChartCard";
import { TraceInfo } from "@/components/TraceInfo";
import { backendFetch } from "@/lib/backend";
import { resolveDashboardScope, scopeToQuery } from "@/lib/dashboard-scope";
import type { DashboardAlerts, DashboardIntegrity } from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function IntegrityPage({
  searchParams,
}: {
  searchParams: Promise<{
    tenant_id?: string | string[];
    from?: string | string[];
    to?: string | string[];
    window_days?: string | string[];
  }>;
}) {
  const resolvedSearchParams = await searchParams;
  const scope = resolveDashboardScope(resolvedSearchParams);
  const baseQuery = scopeToQuery(scope);

  const integrity = await backendFetch<DashboardIntegrity>("/dashboard/integrity", {
    method: "GET",
    query: baseQuery,
  });
  const alerts = await backendFetch<DashboardAlerts>("/dashboard/alerts", {
    method: "GET",
    query: baseQuery,
  });

  const latest = integrity.data.trend[integrity.data.trend.length - 1];
  const chartRows = integrity.data.trend.map((row) => ({
    date_utc: row.date_utc,
    integrity_score: row.integrity_score,
    drift_index: row.drift_index,
    override_rate: row.override_rate,
  }));
  const pointCount = chartRows.length;
  const lastUpdated = latest?.date_utc ?? "—";

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900">Integrity Trends</h1>
          <p className="mt-1 text-sm text-slate-600">Tenant: {scope.tenantId}</p>
        </div>
        <TraceInfo traceId={integrity.data.trace_id ?? integrity.traceId} />
      </div>

      <section className="grid gap-4 md:grid-cols-3">
        <KpiCard
          label="Current Integrity"
          value={(latest?.integrity_score ?? 0).toFixed(2)}
          helper={pointCount <= 1 ? `Last updated: ${lastUpdated}` : "Latest 30-day rollup"}
        />
        <KpiCard label="Current Drift" value={(latest?.drift_index ?? 0).toFixed(4)} />
        <KpiCard
          label="Override Abuse Index"
          value={alerts.data.current_override_abuse_index.toFixed(4)}
          helper="override_rate x actor_concentration"
        />
      </section>

      {pointCount === 0 ? (
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <h3 className="text-base font-semibold text-slate-900">No integrity data yet</h3>
          <p className="mt-2 text-sm text-slate-600">No events recorded for this tenant/date range.</p>
          <p className="mt-1 text-sm text-slate-500">Try expanding the date range or generating transition activity.</p>
        </div>
      ) : (
        <LineChartCard
          title={pointCount === 1 ? "Integrity / Drift / Override Rate (single point)" : "Integrity / Drift / Override Rate"}
          data={chartRows}
          series={[
            { key: "integrity_score", label: "Integrity", color: "#0f766e" },
            { key: "drift_index", label: "Drift", color: "#dc2626" },
            { key: "override_rate", label: "Override Rate", color: "#4338ca" },
          ]}
          height={320}
          showDots={pointCount === 1}
        />
      )}

      <AlertsList alerts={alerts.data.alerts} />
    </div>
  );
}
