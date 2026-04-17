"use client";

import { useState } from "react";
import { callDashboardApi } from "@/lib/api";

interface ROIInputs {
  team_size: number;
  deploys_per_week: number;
  incidents_per_month: number;
  audit_hours_per_year: number;
}

interface ROIResult {
  inputs: ROIInputs & { monthly_license_usd: number };
  monthly_savings_usd: number;
  annual_savings_usd: number;
  net_monthly_benefit_usd: number;
  roi_pct: number;
  payback_months: number | null;
  breakdown: {
    incident_savings_per_month: number;
    audit_savings_per_month: number;
    governance_savings_per_month: number;
  };
  operational: {
    incidents_avoided_per_month: number;
    audit_hours_saved_per_month: number;
    governance_hours_saved_per_month: number;
    risky_deploys_blocked_per_month: number;
  };
  assumptions: Record<string, string>;
}

const fmt = (n: number) =>
  new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 0 }).format(n);

const pct = (n: number) => `${n.toLocaleString()}%`;

const VERDICT_STYLE = (roi: number) =>
  roi >= 500
    ? "border-emerald-200 bg-emerald-50 text-emerald-900"
    : roi >= 200
    ? "border-blue-200 bg-blue-50 text-blue-900"
    : "border-amber-200 bg-amber-50 text-amber-900";

export function ROICalculatorClient() {
  const [inputs, setInputs] = useState<ROIInputs>({
    team_size: 25,
    deploys_per_week: 10,
    incidents_per_month: 2,
    audit_hours_per_year: 120,
  });
  const [result, setResult] = useState<ROIResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const calculate = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await callDashboardApi<ROIResult>(
        "/api/dashboard/commercial/roi-estimate",
        { method: "POST", body: JSON.stringify(inputs) }
      );
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Calculation failed");
    } finally {
      setLoading(false);
    }
  };

  const field = (
    label: string,
    key: keyof ROIInputs,
    min: number,
    max: number,
    step: number,
    unit: string
  ) => (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <label className="text-sm font-medium text-slate-700">{label}</label>
        <span className="text-sm font-bold text-slate-900">
          {inputs[key].toLocaleString()} {unit}
        </span>
      </div>
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={inputs[key]}
        onChange={(e) => setInputs({ ...inputs, [key]: Number(e.target.value) })}
        className="w-full accent-slate-900"
      />
      <div className="flex justify-between text-xs text-slate-400">
        <span>{min.toLocaleString()}</span>
        <span>{max.toLocaleString()}</span>
      </div>
    </div>
  );

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-900">ROI Calculator</h1>
        <p className="mt-1 text-sm text-slate-500">
          Quantify the cost of not having ReleaseGate. Move the sliders to match your team.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-8 lg:grid-cols-2">
        {/* Inputs */}
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-6">
          <h2 className="text-sm font-semibold text-slate-800 uppercase tracking-wide">Your team</h2>
          {field("Engineers on the team", "team_size", 5, 200, 5, "engineers")}
          {field("Production deploys / week", "deploys_per_week", 1, 50, 1, "deploys/wk")}
          {field("Incidents / month", "incidents_per_month", 0, 20, 1, "incidents/mo")}
          {field("Audit prep hours / year", "audit_hours_per_year", 0, 500, 10, "hrs/yr")}
          <button
            onClick={calculate}
            disabled={loading}
            className="w-full rounded-lg bg-slate-900 py-2.5 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-60"
          >
            {loading ? "Calculating…" : "Calculate ROI"}
          </button>
          {error && (
            <p className="text-sm text-rose-600">{error}</p>
          )}
        </div>

        {/* Results */}
        <div className="space-y-4">
          {result ? (
            <>
              {/* Headline */}
              <div className={`rounded-xl border p-6 ${VERDICT_STYLE(result.roi_pct)}`}>
                <p className="text-xs font-semibold uppercase tracking-wide opacity-70">
                  Annual value
                </p>
                <p className="mt-1 text-4xl font-bold">{fmt(result.annual_savings_usd)}</p>
                <p className="mt-2 text-sm font-medium">
                  {pct(result.roi_pct)} ROI
                  {result.payback_months && ` · payback in ${result.payback_months} months`}
                </p>
                <p className="mt-1 text-xs opacity-70">
                  vs. {fmt(result.inputs.monthly_license_usd)}/mo license cost
                </p>
              </div>

              {/* Savings breakdown */}
              <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
                <h3 className="mb-4 text-xs font-semibold uppercase tracking-wide text-slate-500">Monthly savings breakdown</h3>
                {[
                  {
                    label: "Incident reduction",
                    value: result.breakdown.incident_savings_per_month,
                    sub: `${result.operational.incidents_avoided_per_month} incidents avoided/mo`,
                  },
                  {
                    label: "Audit automation",
                    value: result.breakdown.audit_savings_per_month,
                    sub: `${result.operational.audit_hours_saved_per_month} hrs saved/mo`,
                  },
                  {
                    label: "Governance overhead",
                    value: result.breakdown.governance_savings_per_month,
                    sub: `${result.operational.governance_hours_saved_per_month} eng-hrs/mo`,
                  },
                ].map(({ label, value, sub }) => (
                  <div key={label} className="mb-3 last:mb-0">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-slate-700">{label}</span>
                      <span className="text-sm font-bold text-slate-900">{fmt(value)}/mo</span>
                    </div>
                    <p className="text-xs text-slate-400">{sub}</p>
                    <div className="mt-1.5 h-1.5 w-full rounded-full bg-slate-100">
                      <div
                        className="h-1.5 rounded-full bg-slate-700"
                        style={{
                          width: `${Math.min(100, (value / result.monthly_savings_usd) * 100)}%`,
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>

              {/* Operational proof points */}
              <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
                <h3 className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-500">
                  Operational proof points
                </h3>
                <div className="grid grid-cols-2 gap-3">
                  {[
                    { label: "Risky deploys blocked", value: `${result.operational.risky_deploys_blocked_per_month}/mo` },
                    { label: "Incidents avoided",     value: `${result.operational.incidents_avoided_per_month}/mo` },
                    { label: "Audit hours saved",     value: `${result.operational.audit_hours_saved_per_month} hrs/mo` },
                    { label: "Eng-hours reclaimed",   value: `${result.operational.governance_hours_saved_per_month} hrs/mo` },
                  ].map(({ label, value }) => (
                    <div key={label} className="rounded-lg border border-slate-100 bg-slate-50 p-3">
                      <p className="text-xs text-slate-500">{label}</p>
                      <p className="mt-0.5 text-lg font-bold text-slate-900">{value}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Share as case study */}
              <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                <p className="text-xs font-semibold text-slate-700 mb-1">Share this estimate</p>
                <p className="text-xs text-slate-500">
                  A team of <strong>{result.inputs.team_size}</strong> engineers deploying{" "}
                  <strong>{result.inputs.deploys_per_week}×/week</strong> can save{" "}
                  <strong>{fmt(result.annual_savings_usd)}/year</strong> with ReleaseGate —{" "}
                  <strong>{pct(result.roi_pct)} ROI</strong>.
                </p>
              </div>

              {/* Assumptions — visible so buyers can audit the model */}
              <details className="rounded-xl border border-slate-200 bg-white shadow-sm">
                <summary className="cursor-pointer px-5 py-3 text-xs font-semibold text-slate-600 hover:text-slate-900">
                  Model assumptions (conservative) ↓
                </summary>
                <ul className="divide-y divide-slate-50 px-5 pb-4">
                  {Object.entries(result.assumptions).map(([key, label]) => (
                    <li key={key} className="py-2 text-xs text-slate-500">
                      <span className="font-mono text-slate-400 mr-2">{key}</span>{label}
                    </li>
                  ))}
                </ul>
              </details>
            </>
          ) : (
            <div className="flex h-64 items-center justify-center rounded-xl border border-dashed border-slate-200 text-sm text-slate-400">
              Move the sliders and click Calculate ROI
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
