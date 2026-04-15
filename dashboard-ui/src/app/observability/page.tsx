import Link from "next/link";

import { KpiCard } from "@/components/KpiCard";
import { LineChartCard } from "@/components/LineChartCard";
import { TraceInfo } from "@/components/TraceInfo";
import { backendFetch } from "@/lib/backend";
import { resolveDashboardScope, scopeToQuery } from "@/lib/dashboard-scope";
import type {
  DashboardMetricsDrilldown,
  DashboardMetricsSummary,
  DashboardMetricsTimeseries,
  ObservabilityMetric,
} from "@/lib/types";

export const dynamic = "force-dynamic";

const metricOptions: Array<{ key: ObservabilityMetric; label: string }> = [
  { key: "integrity_score", label: "Integrity Score" },
  { key: "drift_index", label: "Drift Index" },
  { key: "override_rate", label: "Override Rate" },
  { key: "block_frequency", label: "Block Frequency" },
];

function asMetric(value: string | string[] | undefined): ObservabilityMetric {
  const raw = Array.isArray(value) ? value[0] : value;
  const normalized = String(raw || "block_frequency").trim().toLowerCase();
  if (normalized === "integrity_score") return "integrity_score";
  if (normalized === "drift_index") return "drift_index";
  if (normalized === "override_rate") return "override_rate";
  return "block_frequency";
}

function displayMetricValue(metric: ObservabilityMetric, value: number): string {
  if (metric === "integrity_score") return value.toFixed(2);
  if (metric === "drift_index") return value.toFixed(4);
  return `${(value * 100).toFixed(2)}%`;
}

function seriesRows(payload: DashboardMetricsTimeseries): Array<Record<string, string | number>> {
  return payload.series.map((point) => ({
    date_utc: point.t.slice(0, 10),
    value: Number(point.value || 0),
  }));
}

function scopedDecisionHref({
  decisionId,
  tenantId,
  fromTs,
  toTs,
}: {
  decisionId: string;
  tenantId: string;
  fromTs: string | null;
  toTs: string | null;
}): string {
  const params = new URLSearchParams();
  if (tenantId) params.set("tenant_id", tenantId);
  if (fromTs) params.set("from", fromTs);
  if (toTs) params.set("to", toTs);
  const query = params.toString();
  return query ? `/decisions/${decisionId}?${query}` : `/decisions/${decisionId}`;
}

export default async function ObservabilityPage({
  searchParams,
}: {
  searchParams: Promise<{
    tenant_id?: string | string[];
    from?: string | string[];
    to?: string | string[];
    window_days?: string | string[];
    metric?: string | string[];
  }>;
}) {
  const resolvedSearchParams = await searchParams;
  const scope = resolveDashboardScope(resolvedSearchParams);
  const baseQuery = scopeToQuery(scope);
  const selectedMetric = asMetric(resolvedSearchParams.metric);

  const [summaryResp, integrityResp, driftResp, overrideResp, blockResp, drilldownResp] = await Promise.all([
    backendFetch<DashboardMetricsSummary>("/dashboard/metrics/summary", {
      method: "GET",
      query: baseQuery,
    }),
    backendFetch<DashboardMetricsTimeseries>("/dashboard/metrics/timeseries", {
      method: "GET",
      query: { ...baseQuery, metric: "integrity_score", bucket: "day" },
    }),
    backendFetch<DashboardMetricsTimeseries>("/dashboard/metrics/timeseries", {
      method: "GET",
      query: { ...baseQuery, metric: "drift_index", bucket: "day" },
    }),
    backendFetch<DashboardMetricsTimeseries>("/dashboard/metrics/timeseries", {
      method: "GET",
      query: { ...baseQuery, metric: "override_rate", bucket: "day" },
    }),
    backendFetch<DashboardMetricsTimeseries>("/dashboard/metrics/timeseries", {
      method: "GET",
      query: { ...baseQuery, metric: "block_frequency", bucket: "day" },
    }),
    backendFetch<DashboardMetricsDrilldown>("/dashboard/metrics/drilldown", {
      method: "GET",
      query: { ...baseQuery, metric: selectedMetric, limit: 50 },
    }),
  ]);

  const summary = summaryResp.data.metrics;
  const traceId = summaryResp.data.trace_id ?? summaryResp.traceId;
  const scopedParams = new URLSearchParams();
  if (scope.tenantId) scopedParams.set("tenant_id", scope.tenantId);
  if (scope.fromTs) scopedParams.set("from", scope.fromTs);
  if (scope.toTs) scopedParams.set("to", scope.toTs);

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900">Observability</h1>
          <p className="mt-1 text-sm text-slate-500">
            Detailed governance metrics for engineering and security teams.
          </p>
        </div>
      </div>
      <details className="text-xs text-slate-400">
        <summary className="cursor-pointer w-fit">Debug</summary>
        <div className="mt-1 space-y-0.5">
          <p className="text-sm text-slate-600">Tenant: {scope.tenantId}</p>
          <TraceInfo traceId={traceId} />
        </div>
      </details>

      <section className="grid gap-4 md:grid-cols-4">
        {metricOptions.map((entry) => (
          <KpiCard
            key={entry.key}
            label={entry.label}
            value={displayMetricValue(entry.key, summary[entry.key].value)}
            helper={
              summary[entry.key].delta === null
                ? "No prior sample"
                : `Δ ${displayMetricValue(entry.key, Number(summary[entry.key].delta || 0))}`
            }
          />
        ))}
      </section>

      <section className="grid gap-4 lg:grid-cols-2">
        <LineChartCard
          title="Integrity Score (time)"
          data={seriesRows(integrityResp.data)}
          series={[{ key: "value", label: "Integrity Score", color: "#0f766e" }]}
          height={280}
        />
        <LineChartCard
          title="Drift Index (time)"
          data={seriesRows(driftResp.data)}
          series={[{ key: "value", label: "Drift Index", color: "#dc2626" }]}
          height={280}
        />
        <LineChartCard
          title="Override Rate (time)"
          data={seriesRows(overrideResp.data)}
          series={[{ key: "value", label: "Override Rate", color: "#4338ca" }]}
          height={280}
        />
        <LineChartCard
          title="Block Frequency (time)"
          data={seriesRows(blockResp.data)}
          series={[{ key: "value", label: "Block Frequency", color: "#7c3aed" }]}
          height={280}
        />
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <h2 className="text-lg font-semibold text-slate-900">Metric Drilldown</h2>
        <p className="mt-1 text-sm text-slate-600">Select a metric to inspect contributing decisions.</p>
        <div className="mt-3 flex flex-wrap gap-2">
          {metricOptions.map((entry) => {
            const params = new URLSearchParams(scopedParams.toString());
            params.set("metric", entry.key);
            const href = `/observability?${params.toString()}`;
            const active = entry.key === selectedMetric;
            return (
              <Link
                key={entry.key}
                href={href}
                className={
                  active
                    ? "rounded-md border border-slate-900 bg-slate-900 px-3 py-1.5 text-sm font-medium text-white"
                    : "rounded-md border border-slate-300 px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50"
                }
              >
                {entry.label}
              </Link>
            );
          })}
        </div>

        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
                <th className="py-2 pr-3">Time</th>
                <th className="py-2 pr-3">Decision</th>
                <th className="py-2 pr-3">Status</th>
                <th className="py-2 pr-3">Issue</th>
                <th className="py-2 pr-3">Workflow / Transition</th>
                <th className="py-2 pr-3">Reason</th>
                <th className="py-2">Link</th>
              </tr>
            </thead>
            <tbody>
              {drilldownResp.data.items.map((item) => (
                <tr key={item.decision_id} className="border-b border-slate-100">
                  <td className="py-2 pr-3 text-slate-600">{new Date(item.created_at).toLocaleString()}</td>
                  <td className="py-2 pr-3 font-mono text-xs text-slate-900">{item.decision_id}</td>
                  <td className="py-2 pr-3 text-slate-700">{item.decision_status}</td>
                  <td className="py-2 pr-3 text-slate-700">{item.jira_issue_id || "-"}</td>
                  <td className="py-2 pr-3 text-slate-700">
                    {item.workflow_id || "-"} / {item.transition_id || "-"}
                  </td>
                  <td className="py-2 pr-3 text-slate-700">{item.reason_code || "-"}</td>
                  <td className="py-2">
                    <a
                      href={scopedDecisionHref({
                        decisionId: item.decision_id,
                        tenantId: scope.tenantId,
                        fromTs: scope.fromTs,
                        toTs: scope.toTs,
                      })}
                      className="text-indigo-600 hover:underline"
                    >
                      View
                    </a>
                  </td>
                </tr>
              ))}
              {!drilldownResp.data.items.length ? (
                <tr>
                  <td className="py-3 text-slate-500" colSpan={7}>
                    No decisions found for this metric/window.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
