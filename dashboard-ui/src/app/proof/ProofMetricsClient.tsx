"use client";

import { useSearchParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { callDashboardApi } from "@/lib/api";

interface CaseStudyRow {
  metric: string;
  before: string;
  after: string;
  improvement: string;
  source?: string;
}

interface ProofData {
  tenant_id: string;
  window_days: number;
  first_decision_at: string | null;
  last_decision_at: string | null;
  total_changes: number;
  full_chain_changes: number;
  traceability_coverage_pct: number;
  orphan_deploys_prevented: number;
  blocked_risky_deploys: number;
  governance_decisions_declared: number;
  deployed_with_decision: number;
  audit_coverage_pct: number;
  mean_time_to_decision_hours: number;
  case_study_table: CaseStudyRow[];
  baseline_note?: string;
}

const IMPROVEMENT_STYLE = (val: string) => {
  if (val.startsWith("-") || val.includes("prevented") || val.includes("Automated") || val.includes("Full"))
    return "text-emerald-700 font-semibold";
  if (val.startsWith("+"))
    return "text-emerald-700 font-semibold";
  return "text-slate-600";
};

export function ProofMetricsClient() {
  const searchParams = useSearchParams();
  const tenantId = searchParams.get("tenant_id") || "default";
  const [days, setDays] = useState(30);
  const [data, setData] = useState<ProofData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const d = await callDashboardApi<ProofData>(
        `/api/dashboard/commercial/proof?tenant_id=${encodeURIComponent(tenantId)}&days=${days}`
      );
      setData(d);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load proof metrics");
    } finally {
      setLoading(false);
    }
  }, [tenantId, days]);

  useEffect(() => { load(); }, [load]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-slate-900">Proof of Value</h1>
          <p className="mt-0.5 text-sm text-slate-500">
            Auto-generated case study data from live governance activity — no manual work required.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <select value={days} onChange={(e) => setDays(Number(e.target.value))}
            className="rounded-md border border-slate-300 px-3 py-1.5 text-sm">
            <option value={30}>Last 30 days</option>
            <option value={60}>Last 60 days</option>
            <option value={90}>Last 90 days</option>
          </select>
          <button onClick={load} disabled={loading}
            className="rounded-md bg-slate-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-60">
            {loading ? "Loading…" : "Refresh"}
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">{error}</div>
      )}

      {data && (
        <>
          {/* Hero metrics */}
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            {[
              {
                label: "Traceability coverage",
                value: `${data.traceability_coverage_pct}%`,
                sub: `${data.full_chain_changes} fully-linked changes`,
                highlight: data.traceability_coverage_pct >= 80,
              },
              {
                label: "Orphan deploys prevented",
                value: data.orphan_deploys_prevented,
                sub: "deploy without PR/Jira stopped",
                highlight: data.orphan_deploys_prevented > 0,
              },
              {
                label: "Risky deploys blocked",
                value: data.blocked_risky_deploys,
                sub: "enforcement violations caught",
                highlight: data.blocked_risky_deploys > 0,
              },
              {
                label: "Audit coverage",
                value: `${data.audit_coverage_pct}%`,
                sub: `${data.deployed_with_decision} deploys with decisions`,
                highlight: data.audit_coverage_pct >= 80,
              },
            ].map(({ label, value, sub, highlight }) => (
              <div key={label} className={`rounded-xl border p-5 shadow-sm ${highlight ? "border-emerald-200 bg-emerald-50" : "border-slate-200 bg-white"}`}>
                <p className="text-xs font-medium text-slate-500 uppercase tracking-wide">{label}</p>
                <p className={`mt-1 text-2xl font-bold ${highlight ? "text-emerald-800" : "text-slate-900"}`}>{value}</p>
                <p className="mt-0.5 text-xs text-slate-400">{sub}</p>
              </div>
            ))}
          </div>

          {/* Case study table */}
          <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
            <div className="border-b border-slate-100 px-5 py-3">
              <h2 className="text-sm font-semibold text-slate-800">Before vs. After</h2>
              <p className="text-xs text-slate-400 mt-0.5">
                &ldquo;Before&rdquo; = industry baseline (labelled per row). &ldquo;After&rdquo; = your actual ReleaseGate data — last {days} days.
              </p>
            </div>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-100 text-left text-xs uppercase tracking-wide text-slate-500">
                  <th className="px-5 py-3 w-1/4">Metric</th>
                  <th className="px-5 py-3">Before</th>
                  <th className="px-5 py-3">After</th>
                  <th className="px-5 py-3">Improvement</th>
                  <th className="px-5 py-3">Source</th>
                </tr>
              </thead>
              <tbody>
                {data.case_study_table.map((row) => (
                  <tr key={row.metric} className="border-b border-slate-50 hover:bg-slate-50">
                    <td className="px-5 py-3 font-medium text-slate-800">{row.metric}</td>
                    <td className="px-5 py-3 text-slate-500">{row.before}</td>
                    <td className="px-5 py-3 font-semibold text-slate-900">{row.after}</td>
                    <td className={`px-5 py-3 ${IMPROVEMENT_STYLE(row.improvement)}`}>{row.improvement}</td>
                    <td className="px-5 py-3 text-xs text-slate-400 italic">{row.source ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {data.baseline_note && (
              <div className="border-t border-slate-100 bg-slate-50 px-5 py-3">
                <p className="text-xs text-slate-500">{data.baseline_note}</p>
              </div>
            )}
          </div>

          {/* Additional context */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <p className="text-xs font-medium text-slate-500 uppercase tracking-wide">Governance decisions</p>
              <p className="mt-1 text-3xl font-bold text-slate-900">{data.governance_decisions_declared}</p>
              <p className="mt-0.5 text-xs text-slate-400">declared in {days}-day window</p>
            </div>
            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <p className="text-xs font-medium text-slate-500 uppercase tracking-wide">Mean time to decision</p>
              <p className="mt-1 text-3xl font-bold text-slate-900">
                {data.mean_time_to_decision_hours > 0 ? `${data.mean_time_to_decision_hours}h` : "—"}
              </p>
              <p className="mt-0.5 text-xs text-slate-400">signal → ALLOWED (avg)</p>
            </div>
            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <p className="text-xs font-medium text-slate-500 uppercase tracking-wide">Full-chain changes</p>
              <p className="mt-1 text-3xl font-bold text-slate-900">{data.full_chain_changes}</p>
              <p className="mt-0.5 text-xs text-slate-400">Jira → PR → Decision → Deploy</p>
            </div>
          </div>

          {/* Shareable testimonial seed — only generated when the data supports a positive story */}
          {(() => {
            const coverage = data.traceability_coverage_pct;
            const blocked = data.blocked_risky_deploys;
            const auditPct = data.audit_coverage_pct;
            // Pick the strongest factual claim. If coverage is above 60%
            // we lead with that ("went from ~55% baseline to X%"); otherwise
            // we lead with blocked deploys or audit coverage — whichever is
            // actually non-zero. If nothing is yet a story, suppress the
            // testimonial rather than produce a negative narrative.
            const strongCoverage = coverage >= 60;
            const haveBlocked = blocked > 0;
            const haveAudit = auditPct >= 50;
            const hasStory = strongCoverage || haveBlocked || haveAudit;

            if (!hasStory) {
              return (
                <div className="rounded-xl border border-dashed border-slate-200 bg-slate-50 p-5">
                  <p className="text-xs font-semibold text-slate-700 mb-1">Testimonial seed — not ready</p>
                  <p className="text-xs text-slate-500">
                    Not enough governance activity in the last {days} days to generate a
                    defensible case-study quote. Extend the window or keep using ReleaseGate
                    for another cycle — proof numbers land once real traffic flows through.
                  </p>
                </div>
              );
            }

            let lead: string;
            if (strongCoverage) {
              lead = `We went from ~55% baseline traceability to ${coverage}% coverage in ${days} days.`;
            } else if (haveBlocked) {
              lead = `ReleaseGate caught ${blocked} risky deploy${blocked === 1 ? "" : "s"} in the last ${days} days that would have shipped otherwise.`;
            } else {
              lead = `${auditPct}% of our deploys now carry a recorded governance decision — audit prep used to be a manual scramble.`;
            }

            return (
              <div className="rounded-xl border border-slate-200 bg-slate-50 p-5">
                <p className="text-xs font-semibold text-slate-700 mb-2">Testimonial seed (auto-generated)</p>
                <blockquote className="text-sm text-slate-700 italic border-l-2 border-slate-300 pl-4">
                  &ldquo;{lead}
                  {haveBlocked && !strongCoverage ? "" : haveBlocked ? ` ReleaseGate caught ${blocked} risky deploy${blocked === 1 ? "" : "s"}.` : ""}
                  {" "}Audit prep that used to take weeks is now automated.&rdquo;
                </blockquote>
                <p className="mt-2 text-xs text-slate-400">
                  Edit this with your customer&apos;s words and use it in outreach.
                </p>
              </div>
            );
          })()}
        </>
      )}
    </div>
  );
}
