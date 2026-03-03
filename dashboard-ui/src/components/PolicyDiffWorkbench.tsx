"use client";

import { useMemo, useState } from "react";

import { DeltaTable } from "@/components/DeltaTable";
import { SeverityBadge } from "@/components/SeverityBadge";
import { TraceInfo } from "@/components/TraceInfo";
import { callDashboardApi } from "@/lib/api";
import type { PolicyDiffResponse, Severity } from "@/lib/types";

const EMPTY_POLICY = JSON.stringify(
  {
    strict_fail_closed: true,
    approval_requirements: { min_approvals: 2, required_roles: ["security", "em"] },
    risk_thresholds: { prod: { max_score: 0.7 } },
    transition_rules: [{ rule_id: "prod-block", transition_id: "31", environment: "prod", result: "BLOCK" }],
  },
  null,
  2,
);

const EMPTY_CANDIDATE = JSON.stringify(
  {
    strict_fail_closed: false,
    approval_requirements: { min_approvals: 1, required_roles: ["security"] },
    risk_thresholds: { prod: { max_score: 0.9 } },
    transition_rules: [{ rule_id: "prod-block", transition_id: "31", environment: "prod", result: "ALLOW" }],
  },
  null,
  2,
);

type Tab = "thresholds" | "conditions" | "roles" | "sod";

export function PolicyDiffWorkbench({ tenantId }: { tenantId: string }) {
  const [currentPolicyJson, setCurrentPolicyJson] = useState(EMPTY_POLICY);
  const [candidatePolicyJson, setCandidatePolicyJson] = useState(EMPTY_CANDIDATE);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PolicyDiffResponse | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>("thresholds");

  const tabRows = useMemo(() => {
    if (!result) return [];
    if (activeTab === "thresholds") return result.threshold_deltas;
    if (activeTab === "conditions") return result.condition_deltas;
    if (activeTab === "roles") return result.role_deltas;
    return result.sod_deltas;
  }, [activeTab, result]);

  return (
    <div className="space-y-6">
      <div className="grid gap-4 lg:grid-cols-2">
        <label className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <p className="text-sm font-semibold text-slate-800">Active Policy JSON</p>
          <textarea
            className="mt-3 h-72 w-full rounded-md border border-slate-200 bg-slate-50 p-2 font-mono text-xs"
            value={currentPolicyJson}
            onChange={(event) => setCurrentPolicyJson(event.target.value)}
          />
        </label>

        <label className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <p className="text-sm font-semibold text-slate-800">Staged Policy JSON</p>
          <textarea
            className="mt-3 h-72 w-full rounded-md border border-slate-200 bg-slate-50 p-2 font-mono text-xs"
            value={candidatePolicyJson}
            onChange={(event) => setCandidatePolicyJson(event.target.value)}
          />
        </label>
      </div>

      <div>
        <button
          type="button"
          disabled={loading}
          className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-60"
          onClick={async () => {
            setLoading(true);
            setError(null);
            try {
              const payload = await callDashboardApi<PolicyDiffResponse>("/api/dashboard/policies/diff", {
                method: "POST",
                body: JSON.stringify({
                  tenant_id: tenantId,
                  current_policy_json: JSON.parse(currentPolicyJson),
                  candidate_policy_json: JSON.parse(candidatePolicyJson),
                }),
              });
              setResult(payload);
            } catch (err) {
              setError(err instanceof Error ? err.message : "Failed to compute policy diff.");
            } finally {
              setLoading(false);
            }
          }}
        >
          {loading ? "Comparing..." : "Compare Policies"}
        </button>
      </div>

      {error ? <p className="text-sm text-rose-700">{error}</p> : null}

      {result ? (
        <>
          <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
            <div className="flex items-center justify-between gap-2">
              <p className="text-sm font-semibold text-slate-800">Summary</p>
              <TraceInfo traceId={result.trace_id} />
            </div>
            <div className="mt-3 flex items-center gap-4 text-sm text-slate-700">
              <span>
                {result.summary.change_count} changes • {result.overall}
              </span>
              <span className="flex items-center gap-1">
                <SeverityBadge severity={"high" satisfies Severity} /> {result.summary.severity_counts.high}
              </span>
              <span className="flex items-center gap-1">
                <SeverityBadge severity={"medium" satisfies Severity} /> {result.summary.severity_counts.medium}
              </span>
              <span className="flex items-center gap-1">
                <SeverityBadge severity={"low" satisfies Severity} /> {result.summary.severity_counts.low}
              </span>
            </div>
            <ul className="mt-3 list-disc space-y-1 pl-5 text-sm text-slate-700">
              {result.summary.summary_bullets.map((bullet, idx) => (
                <li key={`${idx}-${bullet}`}>{bullet}</li>
              ))}
            </ul>
          </div>

          <div className="flex flex-wrap gap-2">
            {(["thresholds", "conditions", "roles", "sod"] as const).map((tab) => (
              <button
                key={tab}
                type="button"
                className={`rounded-md px-3 py-1.5 text-sm ${
                  tab === activeTab
                    ? "bg-slate-900 text-white"
                    : "border border-slate-200 bg-white text-slate-700 hover:bg-slate-50"
                }`}
                onClick={() => setActiveTab(tab)}
              >
                {tab.toUpperCase()}
              </button>
            ))}
          </div>

          <DeltaTable title={`Policy Deltas: ${activeTab.toUpperCase()}`} rows={tabRows as Array<Record<string, unknown> & { severity: Severity }>} />
        </>
      ) : null}
    </div>
  );
}
