import Link from "next/link";

import { KpiCard } from "@/components/KpiCard";
import { LineChartCard } from "@/components/LineChartCard";
import { TraceInfo } from "@/components/TraceInfo";
import { backendFetch } from "@/lib/backend";
import { resolveDashboardScope, scopeToQuery } from "@/lib/dashboard-scope";
import type {
  DashboardCustomerSuccessOverrideAnalysis,
  DashboardCustomerSuccessRegressionReport,
  DashboardCustomerSuccessRiskTrend,
} from "@/lib/types";

export const dynamic = "force-dynamic";

function toSeriesRows(
  points: Array<{ t: string; value: number }>,
): Array<Record<string, string | number>> {
  return points.map((point) => ({
    date_utc: point.t.slice(0, 10),
    value: Number(point.value || 0),
  }));
}

function toPercent(value: number): string {
  return `${(Number(value || 0) * 100).toFixed(2)}%`;
}

function trendLabel(value: number, positiveIsGood: boolean): string {
  const delta = Number(value || 0);
  const signed = delta >= 0 ? `+${delta.toFixed(4)}` : delta.toFixed(4);
  if (positiveIsGood) {
    return delta >= 0 ? `Improving ${signed}` : `Worsening ${signed}`;
  }
  return delta <= 0 ? `Improving ${signed}` : `Worsening ${signed}`;
}

export default async function CustomerSuccessPage({
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
  const query = scopeToQuery(scope);

  const [riskResp, overrideResp, regressionResp] = await Promise.all([
    backendFetch<DashboardCustomerSuccessRiskTrend>("/dashboard/customer_success/risk_trend", {
      method: "GET",
      query,
    }),
    backendFetch<DashboardCustomerSuccessOverrideAnalysis>("/dashboard/customer_success/override_analysis", {
      method: "GET",
      query,
    }),
    backendFetch<DashboardCustomerSuccessRegressionReport>("/dashboard/customer_success/regression_report", {
      method: "GET",
      query,
    }),
  ]);

  const traceId = riskResp.data.trace_id ?? riskResp.traceId;
  const scopedParams = new URLSearchParams();
  if (scope.tenantId) scopedParams.set("tenant_id", scope.tenantId);
  if (scope.fromTs) scopedParams.set("from", scope.fromTs);
  if (scope.toTs) scopedParams.set("to", scope.toTs);
  const scopedQuery = scopedParams.toString();

  const policiesDiffHref = scopedQuery ? `/policies/diff?${scopedQuery}` : "/policies/diff";
  const overridesHref = scopedQuery ? `/overrides?${scopedQuery}` : "/overrides";
  const observabilityHref = scopedQuery ? `/observability?${scopedQuery}` : "/observability";

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900">Executive Impact</h1>
        </div>
      </div>
      <details className="text-xs text-slate-400">
        <summary className="cursor-pointer w-fit">Debug</summary>
        <div className="mt-1 space-y-0.5">
          <p className="text-sm text-slate-600">Tenant: {scope.tenantId}</p>
          <TraceInfo traceId={traceId} />
        </div>
      </details>

      <section className="grid gap-4 md:grid-cols-3">
        <KpiCard
          label="Risk Delta (30d)"
          value={riskResp.data.risk_delta_30d.toFixed(4)}
          helper={trendLabel(riskResp.data.risk_delta_30d, false)}
        />
        <KpiCard
          label="Release Stability Delta"
          value={riskResp.data.release_stability_delta.toFixed(4)}
          helper={trendLabel(riskResp.data.release_stability_delta, true)}
        />
        <KpiCard
          label="Override Concentration"
          value={toPercent(overrideResp.data.override_concentration_index)}
          helper={
            overrideResp.data.policy_weakening_signal
              ? "Weakening signal detected"
              : "No weakening signal"
          }
        />
      </section>

      <section className="grid gap-4 lg:grid-cols-2">
        <LineChartCard
          title="Org Risk Index (time)"
          data={toSeriesRows(riskResp.data.risk_index)}
          series={[{ key: "value", label: "Risk Index", color: "#b91c1c" }]}
          height={280}
        />
        <LineChartCard
          title="Release Stability (time)"
          data={toSeriesRows(riskResp.data.release_stability)}
          series={[{ key: "value", label: "Release Stability", color: "#0f766e" }]}
          height={280}
        />
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-slate-900">Override Behavior Analysis</h2>
          <Link href={overridesHref} className="text-sm text-indigo-600 hover:underline">
            Open Overrides
          </Link>
        </div>
        <p className="mt-1 text-sm text-slate-600">
          Baseline override rate {toPercent(overrideResp.data.override_rate_baseline)} → Recent override rate{" "}
          {toPercent(overrideResp.data.override_rate_recent)}
        </p>

        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
                <th className="py-2 pr-3">User</th>
                <th className="py-2 pr-3">Overrides</th>
                <th className="py-2 pr-3">Share</th>
                <th className="py-2">Last Override</th>
              </tr>
            </thead>
            <tbody>
              {overrideResp.data.top_users.map((item) => (
                <tr key={item.user} className="border-b border-slate-100">
                  <td className="py-2 pr-3 text-slate-900">{item.user}</td>
                  <td className="py-2 pr-3 text-slate-700">{item.overrides}</td>
                  <td className="py-2 pr-3 text-slate-700">{toPercent(item.share)}</td>
                  <td className="py-2 text-slate-600">
                    {item.last_override_at ? new Date(item.last_override_at).toLocaleString() : "-"}
                  </td>
                </tr>
              ))}
              {!overrideResp.data.top_users.length ? (
                <tr>
                  <td className="py-3 text-slate-500" colSpan={4}>
                    No overrides found in this window.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-slate-900">Governance Regression Report</h2>
          <div className="flex items-center gap-4 text-sm">
            <Link href={policiesDiffHref} className="text-indigo-600 hover:underline">
              Open Policy Diff
            </Link>
            <Link href={observabilityHref} className="text-indigo-600 hover:underline">
              Open Decisions
            </Link>
          </div>
        </div>
        <p className="mt-1 text-sm text-slate-600">
          {regressionResp.data.regressions_detected} regressions detected from{" "}
          {regressionResp.data.total_policy_changes} policy changes.
        </p>

        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
                <th className="py-2 pr-3">Changed At</th>
                <th className="py-2 pr-3">Policy</th>
                <th className="py-2 pr-3">Event</th>
                <th className="py-2 pr-3">Integrity Drop</th>
                <th className="py-2 pr-3">Workflows</th>
              </tr>
            </thead>
            <tbody>
              {regressionResp.data.regressions.map((item) => (
                <tr key={item.policy_change_id} className="border-b border-slate-100">
                  <td className="py-2 pr-3 text-slate-600">{new Date(item.changed_at).toLocaleString()}</td>
                  <td className="py-2 pr-3 font-mono text-xs text-slate-900">{item.policy_id}</td>
                  <td className="py-2 pr-3 text-slate-700">{item.event_type}</td>
                  <td className="py-2 pr-3 text-slate-700">{item.integrity_drop.toFixed(2)}</td>
                  <td className="py-2 text-slate-700">{item.affected_workflows.join(", ") || "-"}</td>
                </tr>
              ))}
              {!regressionResp.data.regressions.length ? (
                <tr>
                  <td className="py-3 text-slate-500" colSpan={5}>
                    No governance regressions detected in this window.
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
