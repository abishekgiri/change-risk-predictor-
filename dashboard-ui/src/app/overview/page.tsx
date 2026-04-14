import { BlockedDecisionsTable } from "@/components/BlockedDecisionsTable";
import { KpiCard } from "@/components/KpiCard";
import { LineChartCard } from "@/components/LineChartCard";
import { TraceInfo } from "@/components/TraceInfo";
import { backendFetch } from "@/lib/backend";
import {
  governanceIntegrityLabel,
  plainEnglishRiskCardFromAlert,
  plainEnglishRiskCardFromBlocked,
  plainEnglishRiskCardFromRecommendation,
  severityLabel,
  severityToneClass,
} from "@/lib/clarity";
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
  const integrityLabel = governanceIntegrityLabel(overviewResp.data.integrity_score);
  const hasTrendSignal = trendRows.some(
    (row) => Number(row.integrity || 0) > 0 || Number(row.drift || 0) > 0 || Number(row.override_rate || 0) > 0,
  );

  const topRisks: Array<{
    title: string;
    severity: "high" | "medium" | "low";
    whatHappened: string;
    whyItMatters: string;
    consequence: string;
    whatToDo: string;
    href?: string;
    source: string;
  }> = [];
  for (const alert of alertsResp.data.alerts.slice(0, 5)) {
    const narrative = plainEnglishRiskCardFromAlert(alert);
    topRisks.push({
      title: narrative.title,
      whatHappened: narrative.whatHappened,
      whyItMatters: narrative.whyItMatters,
      consequence: narrative.consequence,
      whatToDo: narrative.whatToDo,
      severity: String(alert.severity).toLowerCase() === "high" ? "high" : String(alert.severity).toLowerCase() === "medium" ? "medium" : "low",
      source: `Alert • ${alert.code}`,
    });
    if (topRisks.length >= 3) break;
  }
  for (const reco of recommendationsResp.data.recommendations) {
    if (topRisks.length >= 3) break;
    const narrative = plainEnglishRiskCardFromRecommendation(reco);
    topRisks.push({
      title: narrative.title,
      whatHappened: narrative.whatHappened,
      whyItMatters: narrative.whyItMatters,
      consequence: narrative.consequence,
      whatToDo: narrative.whatToDo,
      severity: reco.severity === "HIGH" ? "high" : reco.severity === "MEDIUM" ? "medium" : "low",
      source: `Recommended action • ${reco.recommendation_type}`,
    });
  }
  if (topRisks.length < 3 && blockedResp.data.items[0]) {
    const item = blockedResp.data.items[0];
    const narrative = plainEnglishRiskCardFromBlocked(item);
    topRisks.push({
      title: narrative.title,
      whatHappened: narrative.whatHappened,
      whyItMatters: narrative.whyItMatters,
      consequence: narrative.consequence,
      whatToDo: narrative.whatToDo,
      href: `/decisions/${item.decision_id}?tenant_id=${encodeURIComponent(scope.tenantId)}`,
      severity: narrative.severity === "high" ? "high" : narrative.severity === "low" ? "low" : "medium",
      source: "Blocked release",
    });
  }

  const execDashboardItems = [
    {
      label: "Governance Status",
      value:
        releaseStatus === "high_risk" ? "High Risk" : releaseStatus === "caution" ? "Moderate Risk" : "Protected",
      helper: statusTheme.body,
    },
    {
      label: "Priority Issues Today",
      value:
        highAlertCount > 0
          ? `${highAlertCount} high-risk signal${highAlertCount === 1 ? "" : "s"} detected`
          : blockedCountWindow > 0
          ? `${blockedCountWindow} blocked release${blockedCountWindow === 1 ? "" : "s"} detected`
          : "No major gaps detected",
      helper:
        topRisks[0]?.title ||
        "No major governance failures are visible in this reporting window.",
    },
    {
      label: "Control Trend",
      value:
        integrityDelta === null
          ? "Trend pending"
          : integrityDelta >= 0
          ? "Controls improving"
          : "Controls weakening",
      helper:
        overrideDelta === null
          ? changeSummary(integrityDelta, "Governance integrity", "up")
          : `${changeSummary(integrityDelta, "Governance integrity", "up")} ${changeSummary(
              overrideDelta,
              "Exception pressure",
              "down",
            )}`,
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900">Executive Overview</h1>
          <p className="mt-1 text-sm text-slate-600">Tenant: {scope.tenantId}</p>
        </div>
        <TraceInfo traceId={overviewResp.data.trace_id ?? overviewResp.traceId} />
      </div>

      <section className={`rounded-2xl border p-6 shadow-sm ${statusTheme.classes}`}>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wide">Top 3 Risks Today</p>
            <h2 className="mt-2 text-3xl font-semibold">
              {statusTheme.emoji} This Is Why You Should Care Today
            </h2>
            <p className="mt-3 max-w-3xl text-sm">
              The three clearest release risks an executive or operator should act on first. Each card tells you what
              happened, why it matters, what it commonly leads to, and what to do next.
            </p>
          </div>
          <div className="rounded-xl border border-current/30 bg-white/60 px-4 py-3 text-sm">
            <p className="text-xs font-semibold uppercase tracking-wide">Governance Status</p>
            <p className="mt-1 text-xl font-semibold">{execDashboardItems[0].value}</p>
            <p className="mt-1 text-xs">{execDashboardItems[0].helper}</p>
          </div>
        </div>
        <ol className="mt-3 space-y-3">
          {topRisks.slice(0, 3).map((risk, index) => (
            <li key={`${risk.title}-${index}`} className={`rounded-2xl border p-5 shadow-sm ${severityToneClass(risk.severity)}`}>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="text-lg font-semibold">
                  {index + 1}. {risk.title}
                </p>
                <span className="rounded-full border border-current px-2 py-0.5 text-[11px] font-semibold">
                  {severityLabel(risk.severity)}
                </span>
              </div>
              <p className="mt-2 text-xs font-medium uppercase tracking-wide opacity-70">{risk.source}</p>
              <div className="mt-4 grid gap-3 md:grid-cols-4">
                <div className="rounded-md bg-white/70 p-3">
                  <p className="text-[11px] font-semibold uppercase tracking-wide">What happened</p>
                  <p className="mt-2 text-sm">{risk.whatHappened}</p>
                </div>
                <div className="rounded-md bg-white/70 p-3">
                  <p className="text-[11px] font-semibold uppercase tracking-wide">Why it matters</p>
                  <p className="mt-2 text-sm">{risk.whyItMatters}</p>
                </div>
                <div className="rounded-md bg-white/70 p-3">
                  <p className="text-[11px] font-semibold uppercase tracking-wide">Common consequence</p>
                  <p className="mt-2 text-sm">{risk.consequence}</p>
                </div>
                <div className="rounded-md bg-white/70 p-3">
                  <p className="text-[11px] font-semibold uppercase tracking-wide">What to do</p>
                  <p className="mt-2 text-sm">{risk.whatToDo}</p>
                </div>
              </div>
              {risk.href ? (
                <a className="mt-3 inline-block text-sm font-medium text-indigo-700 hover:underline" href={risk.href}>
                  Open full explainer
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
        {execDashboardItems.map((item) => (
          <div key={item.label} className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">{item.label}</p>
            <p className="mt-2 text-2xl font-semibold text-slate-900">{item.value}</p>
            <p className="mt-2 text-sm text-slate-700">{item.helper}</p>
          </div>
        ))}
      </section>

      <section className="grid gap-4 lg:grid-cols-[1.35fr,1fr]">
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Executive Briefing</p>
          <h3 className="mt-2 text-xl font-semibold text-slate-900">{integrityLabel.label} governance posture</h3>
          <p className="mt-2 text-sm text-slate-700">{integrityLabel.explanation}</p>
          <ul className="mt-4 space-y-2 text-sm text-slate-700">
            <li>
              {blockedCountWindow} blocked change{blockedCountWindow === 1 ? "" : "s"} protected this reporting window.
            </li>
            <li>
              {topRisks.length} priority risk{topRisks.length === 1 ? "" : "s"} need attention today across alerts,
              recommendations, or blocked changes.
            </li>
            <li>
              {overviewResp.data.active_strict_modes.length} strict protection scope
              {overviewResp.data.active_strict_modes.length === 1 ? "" : "s"} currently fail closed when evidence is missing.
            </li>
          </ul>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Audit-Friendly Readout</p>
          <h3 className="mt-2 text-lg font-semibold text-slate-900">Change-control posture</h3>
          <p className="mt-2 text-sm text-slate-700">
            Use this view to explain release controls in buyer language: approval discipline, exception pressure, and
            control drift.
          </p>
          <dl className="mt-4 grid gap-3 sm:grid-cols-2">
            <div className="rounded-md bg-slate-50 p-3">
              <dt className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">Open Actions</dt>
              <dd className="mt-1 text-lg font-semibold text-slate-900">{recommendationsResp.data.recommendations.length}</dd>
            </div>
            <div className="rounded-md bg-slate-50 p-3">
              <dt className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">High Alerts</dt>
              <dd className="mt-1 text-lg font-semibold text-slate-900">{highAlertCount}</dd>
            </div>
            <div className="rounded-md bg-slate-50 p-3">
              <dt className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">Strict Modes</dt>
              <dd className="mt-1 text-lg font-semibold text-slate-900">{overviewResp.data.active_strict_modes.length}</dd>
            </div>
            <div className="rounded-md bg-slate-50 p-3">
              <dt className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">Blocked Changes</dt>
              <dd className="mt-1 text-lg font-semibold text-slate-900">{blockedCountWindow}</dd>
            </div>
          </dl>
        </div>
      </section>

      <section className="grid gap-4 md:grid-cols-3">
        <KpiCard
          label="Governance Integrity Score"
          value={overviewResp.data.integrity_score.toFixed(2)}
          helper={`${integrityLabel.label} posture • ${formatSignedPercent(integrityDelta)} vs last week`}
        />
        <KpiCard
          label="Change Control Drift"
          value={driftRisk.label}
          helper={formatRiskHelper(driftRisk.tone)}
        />
        <KpiCard
          label="Override Trend Risk"
          value={bypassRisk.label}
          helper={formatRiskHelper(bypassRisk.tone)}
        />
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <h3 className="text-sm font-semibold text-slate-800">What Changed (Last 7 Days)</h3>
        <ul className="mt-3 space-y-2 text-sm text-slate-700">
          <li>{changeSummary(overrideDelta, "Exception pressure", "down")}</li>
          <li>{changeSummary(driftDelta, "Change-control drift", "down")}</li>
          <li>{changeSummary(integrityDelta, "Governance integrity", "up")}</li>
        </ul>
      </section>

      {hasTrendSignal ? (
        <LineChartCard
          title="Governance Integrity / Drift / Override Trend (30d)"
          data={trendRows}
          series={[
            { key: "integrity", label: "Governance Integrity", color: "#0f766e" },
            { key: "drift", label: "Change Control Drift", color: "#dc2626" },
            { key: "override_rate", label: "Override Trend", color: "#4338ca" },
          ]}
        />
      ) : (
        <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <h3 className="text-sm font-semibold text-slate-800">Governance Trend (30d)</h3>
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

      <details className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <summary className="cursor-pointer text-sm font-semibold text-slate-800">Open detailed blocked release log</summary>
        <div className="mt-4">
          <BlockedDecisionsTable
            tenantId={scope.tenantId}
            fromTs={scope.fromTs}
            toTs={scope.toTs}
            initialItems={blockedResp.data.items}
            initialCursor={blockedResp.data.next_cursor}
          />
        </div>
      </details>
    </div>
  );
}
