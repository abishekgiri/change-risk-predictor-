import { BlockedDecisionsTable } from "@/components/BlockedDecisionsTable";
import { JsonPanel } from "@/components/JsonPanel";
import { KpiCard } from "@/components/KpiCard";
import { LineChartCard } from "@/components/LineChartCard";
import { TraceInfo } from "@/components/TraceInfo";
import { backendFetch } from "@/lib/backend";
import { resolveDashboardScope, scopeToQuery } from "@/lib/dashboard-scope";
import type { DashboardAlerts, DashboardOverview, GovernanceRecommendationsResponse } from "@/lib/types";

interface BlockedPagePayload {
  trace_id: string;
  items: DashboardOverview["recent_blocked"];
  next_cursor: string | null;
}

export const dynamic = "force-dynamic";

export default async function OverviewPage({
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

  const overviewResp = await backendFetch<DashboardOverview>("/dashboard/overview", {
    method: "GET",
    query: {
      ...baseQuery,
      blocked_limit: 25,
    },
  });
  const alertsResp = await backendFetch<DashboardAlerts>("/dashboard/alerts", {
    method: "GET",
    query: baseQuery,
  });
  const blockedResp = await backendFetch<BlockedPagePayload>("/dashboard/blocked", {
    method: "GET",
    query: { ...baseQuery, limit: 25 },
  });
  const recommendationsResp = await backendFetch<GovernanceRecommendationsResponse>("/governance/recommendations", {
    method: "GET",
    query: {
      tenant_id: scope.tenantId,
      lookback_days: scope.windowDays,
      limit: 5,
    },
  });

  const trendRows = overviewResp.data.integrity_trend.map((point, index) => ({
    date_utc: point.date_utc,
    integrity: point.value,
    drift: overviewResp.data.drift_trend[index]?.value ?? 0,
    override_rate: overviewResp.data.override_rate_trend[index]?.value ?? 0,
  }));

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900">Executive Overview</h1>
          <p className="mt-1 text-sm text-slate-600">Tenant: {scope.tenantId}</p>
        </div>
        <TraceInfo traceId={overviewResp.data.trace_id ?? overviewResp.traceId} />
      </div>

      <section className="grid gap-4 md:grid-cols-3">
        <KpiCard label="Integrity Score" value={overviewResp.data.integrity_score.toFixed(2)} />
        <KpiCard label="Drift Index" value={overviewResp.data.drift.current.toFixed(4)} />
        <KpiCard
          label="Override Abuse Index"
          value={alertsResp.data.current_override_abuse_index.toFixed(4)}
          helper="From latest rollup"
        />
      </section>

      <LineChartCard
        title="Integrity / Drift / Override Rate (30d)"
        data={trendRows}
        series={[
          { key: "integrity", label: "Integrity", color: "#0f766e" },
          { key: "drift", label: "Drift", color: "#dc2626" },
          { key: "override_rate", label: "Override Rate", color: "#4338ca" },
        ]}
      />

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <h3 className="text-sm font-semibold text-slate-800">Active Strict Modes</h3>
          <ul className="mt-3 space-y-2 text-sm">
            {overviewResp.data.active_strict_modes.length ? (
              overviewResp.data.active_strict_modes.map((mode) => (
                <li key={`${mode.mode}-${mode.scope_type}-${mode.scope_id}`} className="rounded-md border border-slate-100 p-2">
                  <p className="font-medium text-slate-900">{mode.mode}</p>
                  <p className="text-xs text-slate-600">
                    {mode.scope_type}:{mode.scope_id}
                    {mode.reason ? ` • ${mode.reason}` : ""}
                  </p>
                </li>
              ))
            ) : (
              <li className="text-slate-500">No active strict modes.</li>
            )}
          </ul>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <h3 className="text-sm font-semibold text-slate-800">Recent Alerts</h3>
          <ul className="mt-3 space-y-2 text-sm">
            {alertsResp.data.alerts.slice(0, 5).map((alert) => (
              <li key={`${alert.date_utc}-${alert.code}`} className="rounded-md border border-slate-100 p-2">
                <p className="font-medium text-slate-900">{alert.title}</p>
                <p className="text-xs text-slate-600">
                  {alert.date_utc} • {alert.code} • {String(alert.severity).toUpperCase()}
                </p>
              </li>
            ))}
            {!alertsResp.data.alerts.length ? <li className="text-slate-500">No alerts in window.</li> : null}
          </ul>
        </div>
      </div>

      <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <h3 className="text-sm font-semibold text-slate-800">Governance Health Recommendations</h3>
        <ul className="mt-3 space-y-2 text-sm">
          {recommendationsResp.data.recommendations.slice(0, 5).map((recommendation) => (
            <li key={recommendation.recommendation_id} className="rounded-md border border-slate-100 p-2">
              <p className="font-medium text-slate-900">{recommendation.title}</p>
              <p className="text-xs text-slate-600">
                {recommendation.severity} • {recommendation.recommendation_type} • {recommendation.status}
              </p>
              <p className="mt-1 text-xs text-slate-600">{recommendation.playbook}</p>
            </li>
          ))}
          {!recommendationsResp.data.recommendations.length ? (
            <li className="text-slate-500">No active governance recommendations.</li>
          ) : null}
        </ul>
      </div>

      <BlockedDecisionsTable
        tenantId={scope.tenantId}
        fromTs={scope.fromTs}
        toTs={scope.toTs}
        initialItems={blockedResp.data.items}
        initialCursor={blockedResp.data.next_cursor}
      />

      <JsonPanel title="Drift Breakdown" value={overviewResp.data.drift.breakdown} />
    </div>
  );
}
