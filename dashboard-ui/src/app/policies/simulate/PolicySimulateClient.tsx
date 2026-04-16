"use client";

import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { useState } from "react";
import { callDashboardApi } from "@/lib/api";
import type { PolicySimulationResult } from "@/lib/types";
import { HistoricalSimulationPanel } from "@/components/HistoricalSimulationPanel";

type SimMode = "live" | "historical";

export function PolicySimulateClient() {
  const searchParams = useSearchParams();
  const tenantId = searchParams.get("tenant_id") || "default";
  const preselectedPolicyId = searchParams.get("policy_id") || "";

  const [mode, setMode] = useState<SimMode>(preselectedPolicyId ? "historical" : "live");

  // Live simulation state
  const [transitionId, setTransitionId] = useState("");
  const [projectId, setProjectId] = useState("");
  const [workflowId, setWorkflowId] = useState("");
  const [policyId, setPolicyId] = useState(preselectedPolicyId);
  const [actor, setActor] = useState("");
  const [environment, setEnvironment] = useState("");
  const [liveResult, setLiveResult] = useState<PolicySimulationResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runLiveSimulation = async () => {
    if (!transitionId) {
      setError("Transition ID is required");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const body: Record<string, unknown> = {
        tenant_id: tenantId,
        transition_id: transitionId,
      };
      if (projectId) body.project_id = projectId;
      if (workflowId) body.workflow_id = workflowId;
      if (policyId) body.policy_id = policyId;
      if (actor) body.actor = actor;
      if (environment) body.environment = environment;

      const data = await callDashboardApi<PolicySimulationResult>(
        "/api/dashboard/policies/simulate",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        },
      );
      setLiveResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Simulation failed");
    } finally {
      setLoading(false);
    }
  };

  const scopedHref = (path: string) => {
    const q = searchParams.toString();
    return q ? `${path}?${q}` : path;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <Link
            href={scopedHref("/policies")}
            className="text-sm text-indigo-600 hover:text-indigo-800"
          >
            ← Back to Registry
          </Link>
          <h1 className="mt-2 text-xl font-bold text-slate-900">Policy Simulation</h1>
          <p className="text-sm text-slate-500">
            Test policies against live or historical data before activating.
          </p>
        </div>
      </div>

      {/* Mode toggle */}
      <div className="flex gap-1 rounded-lg bg-slate-100 p-1 w-fit">
        <button
          onClick={() => setMode("live")}
          className={`rounded-md px-4 py-1.5 text-sm font-medium transition-colors ${
            mode === "live"
              ? "bg-white text-slate-900 shadow-sm"
              : "text-slate-600 hover:text-slate-800"
          }`}
        >
          Live Simulation
        </button>
        <button
          onClick={() => setMode("historical")}
          className={`rounded-md px-4 py-1.5 text-sm font-medium transition-colors ${
            mode === "historical"
              ? "bg-white text-slate-900 shadow-sm"
              : "text-slate-600 hover:text-slate-800"
          }`}
        >
          Historical What-If
        </button>
      </div>

      {mode === "live" && (
        <div className="space-y-6">
          {/* Live sim form */}
          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-4">
            <h3 className="text-sm font-semibold text-slate-800">Simulation Parameters</h3>
            <div className="grid grid-cols-2 gap-4">
              <label className="block">
                <span className="text-xs font-medium text-slate-600">
                  Transition ID <span className="text-rose-500">*</span>
                </span>
                <input
                  type="text"
                  value={transitionId}
                  onChange={(e) => setTransitionId(e.target.value)}
                  placeholder="e.g. 41"
                  className="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                />
              </label>
              <label className="block">
                <span className="text-xs font-medium text-slate-600">Policy ID</span>
                <input
                  type="text"
                  value={policyId}
                  onChange={(e) => setPolicyId(e.target.value)}
                  placeholder="Optional — uses active policy"
                  className="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                />
              </label>
              <label className="block">
                <span className="text-xs font-medium text-slate-600">Project ID</span>
                <input
                  type="text"
                  value={projectId}
                  onChange={(e) => setProjectId(e.target.value)}
                  placeholder="Optional"
                  className="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                />
              </label>
              <label className="block">
                <span className="text-xs font-medium text-slate-600">Workflow ID</span>
                <input
                  type="text"
                  value={workflowId}
                  onChange={(e) => setWorkflowId(e.target.value)}
                  placeholder="Optional"
                  className="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                />
              </label>
              <label className="block">
                <span className="text-xs font-medium text-slate-600">Actor</span>
                <input
                  type="text"
                  value={actor}
                  onChange={(e) => setActor(e.target.value)}
                  placeholder="Optional"
                  className="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                />
              </label>
              <label className="block">
                <span className="text-xs font-medium text-slate-600">Environment</span>
                <input
                  type="text"
                  value={environment}
                  onChange={(e) => setEnvironment(e.target.value)}
                  placeholder="e.g. production"
                  className="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                />
              </label>
            </div>
            <button
              onClick={runLiveSimulation}
              disabled={loading}
              className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-60"
            >
              {loading ? "Simulating..." : "Run Simulation"}
            </button>
          </div>

          {error && (
            <div className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
              {error}
            </div>
          )}

          {/* Live simulation result */}
          {liveResult && (
            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-4">
              <h3 className="text-sm font-semibold text-slate-800">Simulation Result</h3>

              {/* Verdict */}
              <div
                className={`flex items-center gap-3 rounded-lg border px-5 py-4 ${
                  liveResult.status === "ALLOWED"
                    ? "border-emerald-200 bg-emerald-50"
                    : liveResult.status === "BLOCKED"
                      ? "border-rose-200 bg-rose-50"
                      : "border-amber-200 bg-amber-50"
                }`}
              >
                <span className="text-3xl">
                  {liveResult.status === "ALLOWED"
                    ? "✓"
                    : liveResult.status === "BLOCKED"
                      ? "✕"
                      : "⚠"}
                </span>
                <div>
                  <p
                    className={`text-lg font-bold ${
                      liveResult.status === "ALLOWED"
                        ? "text-emerald-800"
                        : liveResult.status === "BLOCKED"
                          ? "text-rose-800"
                          : "text-amber-800"
                    }`}
                  >
                    {liveResult.status}
                  </p>
                  {liveResult.reason_codes.length > 0 && (
                    <p className="text-sm text-slate-600">
                      {liveResult.reason_codes.join(", ")}
                    </p>
                  )}
                </div>
              </div>

              {/* Details grid */}
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                <div className="rounded-lg border border-slate-100 px-3 py-2">
                  <p className="text-xs text-slate-500">Enforced</p>
                  <p className="text-sm font-semibold">{liveResult.enforced ? "Yes" : "No"}</p>
                </div>
                <div className="rounded-lg border border-slate-100 px-3 py-2">
                  <p className="text-xs text-slate-500">Policies Resolved</p>
                  <p className="text-sm font-semibold">{liveResult.component_policy_ids.length}</p>
                </div>
                <div className="rounded-lg border border-slate-100 px-3 py-2">
                  <p className="text-xs text-slate-500">Warnings</p>
                  <p className="text-sm font-semibold">{liveResult.warnings.length}</p>
                </div>
                <div className="rounded-lg border border-slate-100 px-3 py-2">
                  <p className="text-xs text-slate-500">Coverage Gaps</p>
                  <p className="text-sm font-semibold">{liveResult.coverage_gaps.length}</p>
                </div>
              </div>

              {/* Lineage */}
              {Object.keys(liveResult.component_lineage).length > 0 && (
                <div>
                  <h4 className="text-xs font-semibold text-slate-600 uppercase tracking-wide mb-2">
                    Resolution Lineage
                  </h4>
                  <div className="space-y-1">
                    {Object.entries(liveResult.component_lineage).map(([scope, entry]) => (
                      <div
                        key={scope}
                        className="flex items-center gap-2 rounded bg-slate-50 px-3 py-1.5 text-xs"
                      >
                        <span className="font-semibold text-slate-700 uppercase w-20">
                          {scope}
                        </span>
                        <span className="font-mono text-slate-500">{entry.scope_id}</span>
                        <span className="text-slate-300">|</span>
                        <span className="text-slate-500">v{entry.version}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Matched rule */}
              {liveResult.matched_rule && (
                <div>
                  <h4 className="text-xs font-semibold text-slate-600 uppercase tracking-wide mb-2">
                    Matched Rule
                  </h4>
                  <pre className="rounded-lg bg-slate-50 p-3 text-xs font-mono text-slate-700 border border-slate-100 overflow-auto max-h-48">
                    {JSON.stringify(liveResult.matched_rule, null, 2)}
                  </pre>
                </div>
              )}

              {/* Effective policy */}
              <details>
                <summary className="cursor-pointer text-xs font-medium text-slate-500 hover:text-slate-700">
                  Effective Policy JSON
                </summary>
                <pre className="mt-2 rounded-lg bg-slate-50 p-3 text-xs font-mono text-slate-700 border border-slate-100 overflow-auto max-h-64">
                  {JSON.stringify(liveResult.effective_policy_json, null, 2)}
                </pre>
              </details>
            </div>
          )}
        </div>
      )}

      {mode === "historical" && (
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <h3 className="text-sm font-semibold text-slate-800 mb-1">Historical What-If Analysis</h3>
          <p className="text-xs text-slate-500 mb-4">
            Replay past decisions against a policy to predict what would change.
          </p>
          <HistoricalSimulationPanel
            tenantId={tenantId}
            policyId={preselectedPolicyId || undefined}
          />
        </div>
      )}
    </div>
  );
}
