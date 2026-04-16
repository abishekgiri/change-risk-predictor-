"use client";

import { useState } from "react";
import type { HistoricalSimulationResult } from "@/lib/types";
import { callDashboardApi } from "@/lib/api";

interface Props {
  tenantId: string;
  policyId?: string;
  policyJson?: Record<string, unknown>;
}

export function HistoricalSimulationPanel({ tenantId, policyId, policyJson }: Props) {
  const [result, setResult] = useState<HistoricalSimulationResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [windowDays, setWindowDays] = useState(30);

  const runSimulation = async () => {
    setLoading(true);
    setError(null);
    try {
      const body: Record<string, unknown> = {
        tenant_id: tenantId,
        time_window_days: windowDays,
      };
      if (policyId) body.policy_id = policyId;
      if (policyJson) body.policy_json = policyJson;

      const data = await callDashboardApi<HistoricalSimulationResult>(
        "/api/dashboard/policies/simulate-historical",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        },
      );
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Simulation failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Controls */}
      <div className="flex items-end gap-3">
        <label className="flex flex-col text-xs font-medium text-slate-600">
          Time window
          <select
            value={windowDays}
            onChange={(e) => setWindowDays(Number(e.target.value))}
            className="mt-1 rounded-md border border-slate-300 px-2 py-1.5 text-sm"
          >
            <option value={30}>Last 30 days</option>
            <option value={60}>Last 60 days</option>
            <option value={90}>Last 90 days</option>
          </select>
        </label>
        <button
          onClick={runSimulation}
          disabled={loading}
          className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-60"
        >
          {loading ? "Simulating..." : "Run Historical Simulation"}
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
          {error}
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-4">
          {/* Summary KPIs */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <SimKpi label="Events Scanned" value={result.scanned_events} />
            <SimKpi label="Simulated" value={result.simulated_events} />
            <SimKpi
              label="Would Block"
              value={result.would_block_count}
              highlight={result.would_block_count > 0 ? "rose" : undefined}
            />
            <SimKpi
              label="Would Allow"
              value={result.would_allow_count}
              highlight={result.would_allow_count > 0 ? "emerald" : undefined}
            />
          </div>

          {/* Delta breakdown */}
          <div className="rounded-lg border border-slate-200 bg-white p-4">
            <h4 className="text-sm font-semibold text-slate-800 mb-3">Impact Breakdown</h4>
            <div className="grid grid-cols-3 gap-4">
              <div className="text-center">
                <p className="text-2xl font-bold text-rose-600">
                  {result.delta_breakdown.allow_to_deny}
                </p>
                <p className="text-xs text-slate-500">Allow → Deny</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-emerald-600">
                  {result.delta_breakdown.deny_to_allow}
                </p>
                <p className="text-xs text-slate-500">Deny → Allow</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-slate-500">
                  {result.delta_breakdown.unchanged}
                </p>
                <p className="text-xs text-slate-500">Unchanged</p>
              </div>
            </div>

            {/* Impact bar */}
            {result.simulated_events > 0 && (
              <div className="mt-3">
                <div className="flex h-3 overflow-hidden rounded-full bg-slate-100">
                  {result.delta_breakdown.allow_to_deny > 0 && (
                    <div
                      className="bg-rose-400"
                      style={{
                        width: `${(result.delta_breakdown.allow_to_deny / result.simulated_events) * 100}%`,
                      }}
                    />
                  )}
                  {result.delta_breakdown.deny_to_allow > 0 && (
                    <div
                      className="bg-emerald-400"
                      style={{
                        width: `${(result.delta_breakdown.deny_to_allow / result.simulated_events) * 100}%`,
                      }}
                    />
                  )}
                  <div className="flex-1 bg-slate-200" />
                </div>
                <div className="mt-1 flex justify-between text-[10px] text-slate-400">
                  <span>Newly blocked</span>
                  <span>Newly allowed</span>
                  <span>Unchanged</span>
                </div>
              </div>
            )}
          </div>

          {/* Deny reasons histogram */}
          {result.deny_reasons_histogram.length > 0 && (
            <div className="rounded-lg border border-slate-200 bg-white p-4">
              <h4 className="text-sm font-semibold text-slate-800 mb-3">Block Reasons</h4>
              <div className="space-y-2">
                {result.deny_reasons_histogram.map((item) => {
                  const maxCount = Math.max(
                    ...result.deny_reasons_histogram.map((h) => h.count),
                  );
                  return (
                    <div key={item.reason} className="flex items-center gap-3">
                      <span className="w-40 truncate text-xs font-mono text-slate-600">
                        {item.reason}
                      </span>
                      <div className="flex-1">
                        <div className="h-4 overflow-hidden rounded bg-slate-100">
                          <div
                            className="h-full rounded bg-rose-300"
                            style={{ width: `${(item.count / maxCount) * 100}%` }}
                          />
                        </div>
                      </div>
                      <span className="w-10 text-right text-xs font-semibold text-slate-700">
                        {item.count}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Impacted workflows */}
          {result.impacted_workflows.length > 0 && (
            <div className="rounded-lg border border-slate-200 bg-white p-4">
              <h4 className="text-sm font-semibold text-slate-800 mb-3">
                Most Impacted Workflows
              </h4>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-slate-100 text-left text-xs uppercase tracking-wide text-slate-500">
                      <th className="pb-2 pr-4">Workflow</th>
                      <th className="pb-2 pr-4">Events</th>
                      <th className="pb-2">Impact</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.impacted_workflows.slice(0, 10).map((wf, i) => (
                      <tr key={i} className="border-b border-slate-50">
                        <td className="py-2 pr-4 font-mono text-xs">
                          {String(wf.workflow_id || wf.workflow || "unknown")}
                        </td>
                        <td className="py-2 pr-4 text-xs">
                          {String(wf.event_count || wf.count || 0)}
                        </td>
                        <td className="py-2 text-xs">
                          {String(wf.would_block || wf.block_count || 0)} would block
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function SimKpi({
  label,
  value,
  highlight,
}: {
  label: string;
  value: number;
  highlight?: "rose" | "emerald";
}) {
  const textColor = highlight === "rose"
    ? "text-rose-700"
    : highlight === "emerald"
      ? "text-emerald-700"
      : "text-slate-800";
  const bgColor = highlight === "rose"
    ? "bg-rose-50 border-rose-200"
    : highlight === "emerald"
      ? "bg-emerald-50 border-emerald-200"
      : "bg-white border-slate-200";

  return (
    <div className={`rounded-lg border px-3 py-2 ${bgColor}`}>
      <p className={`text-2xl font-bold ${textColor}`}>{value.toLocaleString()}</p>
      <p className="text-xs text-slate-500">{label}</p>
    </div>
  );
}
