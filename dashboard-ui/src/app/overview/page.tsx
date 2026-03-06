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

type RiskStatus = "safe" | "caution" | "high_risk";

function percentChange(current: number, previous: number): number | null {
  if (!Number.isFinite(current) || !Number.isFinite(previous)) return null;
  if (previous === 0) {
    if (current === 0) return 0;
    return null;
  }
  return ((current - previous) / Math.abs(previous)) * 100;
}

function riskBand(value: number): { label: string; tone: "low" | "medium" | "high" } {
  if (value >= 0.6) return { label: "High", tone: "high" };
  if (value >= 0.25) return { label: "Moderate", tone: "medium" };
  return { label: "Low", tone: "low" };
}

function driftBand(value: number): { label: string; tone: "low" | "medium" | "high" } {
  if (value >= 0.4) return { label: "High", tone: "high" };
  if (value >= 0.15) return { label: "Moderate", tone: "medium" };
  return { label: "Low", tone: "low" };
}

function formatSignedPercent(delta: number | null): string {
  if (delta === null) return "n/a";
  const rounded = Math.round(delta * 10) / 10;
  return `${rounded > 0 ? "+" : ""}${rounded}%`;
}

function formatRiskHelper(band: "low" | "medium" | "high"): string {
  if (band === "high") return "Elevated risk. Review controls today.";
  if (band === "medium") return "Moderate risk. Monitor closely.";
  return "Within normal range.";
}

function changeSummary(
  delta: number | null,
  noun: string,
  improvedDirection: "up" | "down",
): string {
  if (delta === null) return `${noun} trend unavailable this week.`;
  if (Math.abs(delta) < 1) return `${noun} remained stable this week.`;
  const movedUp = delta > 0;
  const improved = improvedDirection === "up" ? movedUp : !movedUp;
  return `${noun} ${improved ? "improved" : "worsened"} ${formatSignedPercent(Math.abs(delta))} vs prior week.`;
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
  let recommendationsResp:
    | { data: GovernanceRecommendationsResponse; traceId: string | null; status: number }
    | null = null;
  try {
    recommendationsResp = await backendFetch<GovernanceRecommendationsResponse>("/governance/recommendations", {
      method: "GET",
      query: {
        tenant_id: scope.tenantId,
        lookback_days: scope.windowDays,
        limit: 5,
      },
    });
  } catch {
    recommendationsResp = {
      data: {
        tenant_id: scope.tenantId,
        generated_at: null,
        lookback_days: scope.windowDays,
        insight: {},
        recommendations: [],
      },
      traceId: null,
      status: 500,
    };
  }

  const trendRows = overviewResp.data.integrity_trend.map((point, index) => ({
    date_utc: point.date_utc,
    integrity: point.value,
    drift: overviewResp.data.drift_trend[index]?.value ?? 0,
    override_rate: overviewResp.data.override_rate_trend[index]?.value ?? 0,
  }));

  const highAlertCount = alertsResp.data.alerts.filter((alert) => String(alert.severity).toLowerCase() === "high").length;
  const mediumAlertCount = alertsResp.data.alerts.filter((alert) => String(alert.severity).toLowerCase() === "medium").length;
  const highRecoCount = recommendationsResp.data.recommendations.filter((item) => item.severity === "HIGH").length;
  const mediumRecoCount = recommendationsResp.data.recommendations.filter((item) => item.severity === "MEDIUM").length;
  const blockedCountWindow = blockedResp.data.items.length;

  const releaseStatus: RiskStatus =
    highAlertCount > 0 || highRecoCount > 0
      ? "high_risk"
      : mediumAlertCount > 0 || mediumRecoCount > 0 || blockedCountWindow > 0
      ? "caution"
      : "safe";

  const statusTheme = {
    safe: {
      badge: "SAFE TO SHIP",
      emoji: "🟢",
      classes: "border-emerald-200 bg-emerald-50 text-emerald-900",
      body: "Governance controls are operating normally. No elevated bypass or approval drift detected.",
    },
    caution: {
      badge: "CAUTION ADVISED",
      emoji: "🟡",
      classes: "border-amber-200 bg-amber-50 text-amber-900",
      body: "Governance controls are active, but risk signals are rising. Review high-impact workflows before shipping.",
    },
    high_risk: {
      badge: "HIGH RISK",
      emoji: "🔴",
      classes: "border-rose-200 bg-rose-50 text-rose-900",
      body: "Critical governance protections are weakening. Shipping now increases operational risk.",
    },
  }[releaseStatus];

  const recentWeek = trendRows.slice(-7);
  const previousWeek = trendRows.slice(Math.max(0, trendRows.length - 14), Math.max(0, trendRows.length - 7));
  const recentOverrideAvg =
    recentWeek.reduce((sum, item) => sum + Number(item.override_rate || 0), 0) / Math.max(recentWeek.length, 1);
  const previousOverrideAvg =
    previousWeek.reduce((sum, item) => sum + Number(item.override_rate || 0), 0) / Math.max(previousWeek.length, 1);
  const recentDriftAvg =
    recentWeek.reduce((sum, item) => sum + Number(item.drift || 0), 0) / Math.max(recentWeek.length, 1);
  const previousDriftAvg =
    previousWeek.reduce((sum, item) => sum + Number(item.drift || 0), 0) / Math.max(previousWeek.length, 1);
  const currentIntegrity = recentWeek[recentWeek.length - 1]?.integrity ?? overviewResp.data.integrity_score;
  const previousIntegrity =
    previousWeek[previousWeek.length - 1]?.integrity ??
    recentWeek[0]?.integrity ??
    overviewResp.data.integrity_score;
  const overrideDelta = percentChange(recentOverrideAvg, previousOverrideAvg);
  const driftDelta = percentChange(recentDriftAvg, previousDriftAvg);
  const integrityDelta = percentChange(currentIntegrity, previousIntegrity);
  const driftRisk = driftBand(overviewResp.data.drift.current);
  const bypassRisk = riskBand(alertsResp.data.current_override_abuse_index);
  const hasTrendSignal = trendRows.some(
    (row) => Number(row.integrity || 0) > 0 || Number(row.drift || 0) > 0 || Number(row.override_rate || 0) > 0,
  );

  const topRisks: Array<{ title: string; detail: string; href?: string; severity: "high" | "medium" | "low" }> = [];
  for (const alert of alertsResp.data.alerts.slice(0, 5)) {
    topRisks.push({
      title: alert.title,
      detail: `${alert.code} • ${String(alert.severity).toUpperCase()}`,
      severity: String(alert.severity).toLowerCase() === "high" ? "high" : String(alert.severity).toLowerCase() === "medium" ? "medium" : "low",
    });
    if (topRisks.length >= 3) break;
  }
  for (const reco of recommendationsResp.data.recommendations) {
    if (topRisks.length >= 3) break;
    topRisks.push({
      title: reco.title,
      detail: reco.playbook,
      severity: reco.severity === "HIGH" ? "high" : reco.severity === "MEDIUM" ? "medium" : "low",
    });
  }
  if (topRisks.length < 3 && blockedResp.data.items[0]) {
    const item = blockedResp.data.items[0];
    topRisks.push({
      title: "Recent blocked change needs review",
      detail: `${item.workflow || "workflow"} / ${item.transition || "transition"} • ${item.reason_code || "policy blocked"}`,
      href: `/decisions/${item.decision_id}?tenant_id=${encodeURIComponent(scope.tenantId)}`,
      severity: "medium",
    });
  }

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900">Executive Overview</h1>
          <p className="mt-1 text-sm text-slate-600">Tenant: {scope.tenantId}</p>
        </div>
        <TraceInfo traceId={overviewResp.data.trace_id ?? overviewResp.traceId} />
      </div>

      <section className={`rounded-xl border p-5 shadow-sm ${statusTheme.classes}`}>
        <p className="text-xs font-semibold uppercase tracking-wide">Release Risk Status</p>
        <h2 className="mt-2 text-2xl font-semibold">
          {statusTheme.emoji} {statusTheme.badge}
        </h2>
        <p className="mt-2 text-sm">{statusTheme.body}</p>
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <h3 className="text-sm font-semibold text-slate-800">Top 3 Risks Today</h3>
        <p className="mt-1 text-xs text-slate-500">Highest governance risks requiring attention now.</p>
        <ol className="mt-3 space-y-3">
          {topRisks.slice(0, 3).map((risk, index) => (
            <li key={`${risk.title}-${index}`} className="rounded-md border border-slate-100 p-3">
              <p className="text-sm font-medium text-slate-900">
                {index + 1}. {risk.title}
              </p>
              <p className="mt-1 text-xs text-slate-600">{risk.detail}</p>
              {risk.href ? (
                <a className="mt-2 inline-block text-xs text-indigo-700 hover:underline" href={risk.href}>
                  View details
                </a>
              ) : null}
            </li>
          ))}
          {topRisks.length === 0 ? (
            <li className="text-sm text-slate-500">
              No critical governance risks detected. All monitored workflows are operating within policy.
            </li>
          ) : null}
        </ol>
      </section>

      <section className="grid gap-4 md:grid-cols-3">
        <KpiCard
          label="Release Safety Score"
          value={overviewResp.data.integrity_score.toFixed(2)}
          helper={`${formatSignedPercent(integrityDelta)} vs last week`}
        />
        <KpiCard
          label="Process Drift Risk"
          value={driftRisk.label}
          helper={formatRiskHelper(driftRisk.tone)}
        />
        <KpiCard
          label="Policy Bypass Risk"
          value={bypassRisk.label}
          helper={formatRiskHelper(bypassRisk.tone)}
        />
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <h3 className="text-sm font-semibold text-slate-800">What Changed (Last 7 Days)</h3>
        <ul className="mt-3 space-y-2 text-sm text-slate-700">
          <li>{changeSummary(overrideDelta, "Policy bypass risk", "down")}</li>
          <li>{changeSummary(driftDelta, "Process drift risk", "down")}</li>
          <li>{changeSummary(integrityDelta, "Release safety score", "up")}</li>
        </ul>
      </section>

      {hasTrendSignal ? (
        <LineChartCard
          title="Release Safety / Process Drift / Policy Bypass Trends (30d)"
          data={trendRows}
          series={[
            { key: "integrity", label: "Release Safety", color: "#0f766e" },
            { key: "drift", label: "Process Drift Risk", color: "#dc2626" },
            { key: "override_rate", label: "Policy Bypass Risk", color: "#4338ca" },
          ]}
        />
      ) : (
        <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <h3 className="text-sm font-semibold text-slate-800">Risk Trends (30d)</h3>
          <p className="mt-2 text-sm text-slate-600">
            No significant risk trends detected in the past 30 days. Governance activity remains stable.
          </p>
        </section>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <h3 className="text-sm font-semibold text-slate-800">Protection Level</h3>
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
          <h3 className="text-sm font-semibold text-slate-800">Why Changes Were Blocked</h3>
          <ul className="mt-3 space-y-2 text-sm">
            {blockedResp.data.items[0] ? (
              <li className="rounded-md border border-slate-100 p-3">
                <p className="font-medium text-slate-900">Most recent blocked transition</p>
                <p className="mt-1 text-xs text-slate-600">
                  Workflow: {blockedResp.data.items[0].workflow || "-"} / {blockedResp.data.items[0].transition || "-"}
                </p>
                <p className="mt-1 text-xs text-slate-600">Reason: {blockedResp.data.items[0].reason_code || "Policy blocked"}</p>
                <a
                  className="mt-2 inline-block text-xs text-indigo-700 hover:underline"
                  href={`/decisions/${blockedResp.data.items[0].decision_id}?tenant_id=${encodeURIComponent(scope.tenantId)}`}
                >
                  Open “Why blocked” explainer
                </a>
              </li>
            ) : (
              <li className="text-slate-500">No blocked changes in this window.</li>
            )}
          </ul>
        </div>
      </div>

      <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <h3 className="text-sm font-semibold text-slate-800">Recommended Actions</h3>
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
