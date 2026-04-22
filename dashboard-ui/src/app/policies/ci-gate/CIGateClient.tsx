"use client";

import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { useState } from "react";
import { callDashboardApi } from "@/lib/api";

interface CIValidateResult {
  verdict: "PASS" | "FAIL";
  tenant_id: string;
  policy_ref: Record<string, unknown>;
  failure_reasons: string[];
  lint: {
    ok: boolean;
    error_count: number;
    warning_count: number;
    errors: Array<{ code: string; message: string; severity: string }>;
    warnings: Array<{ code: string; message: string; severity: string }>;
  };
  conflicts: {
    ok: boolean;
    contradiction_count: number;
    shadowed_rule_count: number;
    coverage_gap_count: number;
    contradictions: Array<{ code: string; message: string }>;
    shadowed_rules: Array<{ code: string; message: string }>;
    coverage_gaps: Array<{ code: string; message: string }>;
  };
  simulation: {
    scanned_events?: number;
    simulated_events?: number;
    would_block_count?: number;
    would_allow_count?: number;
    delta_breakdown?: { allow_to_deny: number; deny_to_allow: number; unchanged: number };
    error?: string;
  } | null;
}

export function CIGateClient() {
  const searchParams = useSearchParams();
  const tenantId = searchParams.get("tenant_id") || "";
  const preselectedPolicyId = searchParams.get("policy_id") || "";

  const [policyId, setPolicyId] = useState(preselectedPolicyId);
  const [policyJson, setPolicyJson] = useState("");
  const [inputMode, setInputMode] = useState<"registry" | "json">(preselectedPolicyId ? "registry" : "json");
  const [failOnWarnings, setFailOnWarnings] = useState(false);
  const [runSimulation, setRunSimulation] = useState(true);
  const [windowDays, setWindowDays] = useState(30);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<CIValidateResult | null>(null);

  const handleValidate = async () => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const body: Record<string, unknown> = {
        tenant_id: tenantId,
        fail_on_warnings: failOnWarnings,
        run_historical_simulation: runSimulation,
        simulation_window_days: windowDays,
      };
      if (inputMode === "registry" && policyId) {
        body.policy_id = policyId;
      } else if (inputMode === "json" && policyJson) {
        body.policy_json = JSON.parse(policyJson);
      } else {
        setError("Provide either a policy ID or policy JSON");
        setLoading(false);
        return;
      }
      const data = await callDashboardApi<CIValidateResult>(
        "/api/dashboard/policies/ci-validate",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        },
      );
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Validation failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <Link
          href={`/policies?tenant_id=${encodeURIComponent(tenantId)}`}
          className="text-sm text-indigo-600 hover:text-indigo-800"
        >
          ← Back to Registry
        </Link>
        <h1 className="mt-2 text-xl font-bold text-slate-900">CI Gate Validation</h1>
        <p className="text-sm text-slate-500">
          Pre-merge validation: lint, conflict detection, shadowing analysis, and historical impact.
        </p>
      </div>

      {/* Input mode toggle */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-4">
        <div className="flex gap-1 rounded-lg bg-slate-100 p-1 w-fit">
          <button
            onClick={() => setInputMode("registry")}
            className={`rounded-md px-4 py-1.5 text-sm font-medium ${
              inputMode === "registry" ? "bg-white text-slate-900 shadow-sm" : "text-slate-600"
            }`}
          >
            From Registry
          </button>
          <button
            onClick={() => setInputMode("json")}
            className={`rounded-md px-4 py-1.5 text-sm font-medium ${
              inputMode === "json" ? "bg-white text-slate-900 shadow-sm" : "text-slate-600"
            }`}
          >
            Inline JSON
          </button>
        </div>

        {inputMode === "registry" ? (
          <label className="block">
            <span className="text-xs font-medium text-slate-600">Policy ID</span>
            <input
              type="text"
              value={policyId}
              onChange={(e) => setPolicyId(e.target.value)}
              placeholder="e.g. pol_abc123"
              className="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm font-mono"
            />
          </label>
        ) : (
          <label className="block">
            <span className="text-xs font-medium text-slate-600">Policy JSON</span>
            <textarea
              value={policyJson}
              onChange={(e) => setPolicyJson(e.target.value)}
              rows={10}
              spellCheck={false}
              placeholder='{"rules": [...], "risk_thresholds": {...}}'
              className="mt-1 block w-full rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 font-mono text-xs"
            />
          </label>
        )}

        {/* Options */}
        <div className="flex flex-wrap items-center gap-4">
          <label className="flex items-center gap-2 text-sm text-slate-700">
            <input
              type="checkbox"
              checked={failOnWarnings}
              onChange={(e) => setFailOnWarnings(e.target.checked)}
              className="rounded border-slate-300"
            />
            Fail on warnings (strict mode)
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-700">
            <input
              type="checkbox"
              checked={runSimulation}
              onChange={(e) => setRunSimulation(e.target.checked)}
              className="rounded border-slate-300"
            />
            Run historical simulation
          </label>
          {runSimulation && (
            <select
              value={windowDays}
              onChange={(e) => setWindowDays(Number(e.target.value))}
              className="rounded-md border border-slate-300 px-2 py-1.5 text-sm"
            >
              <option value={30}>30 days</option>
              <option value={60}>60 days</option>
              <option value={90}>90 days</option>
            </select>
          )}
        </div>

        <button
          onClick={handleValidate}
          disabled={loading}
          className="rounded-lg bg-slate-900 px-6 py-2.5 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-60"
        >
          {loading ? "Validating..." : "Run CI Validation"}
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
          {error}
        </div>
      )}

      {/* Result */}
      {result && (
        <div className="space-y-4">
          {/* Verdict banner */}
          <div
            className={`flex items-center gap-4 rounded-xl border-2 px-6 py-5 ${
              result.verdict === "PASS"
                ? "border-emerald-300 bg-emerald-50"
                : "border-rose-300 bg-rose-50"
            }`}
          >
            <span className="text-4xl">
              {result.verdict === "PASS" ? "✓" : "✕"}
            </span>
            <div>
              <p
                className={`text-2xl font-bold ${
                  result.verdict === "PASS" ? "text-emerald-800" : "text-rose-800"
                }`}
              >
                {result.verdict}
              </p>
              {result.failure_reasons.length > 0 && (
                <ul className="mt-1 text-sm text-slate-600">
                  {result.failure_reasons.map((r, i) => (
                    <li key={i}>— {r}</li>
                  ))}
                </ul>
              )}
            </div>
          </div>

          {/* Check details grid */}
          <div className="grid gap-4 sm:grid-cols-3">
            {/* Lint */}
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
              <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-2">
                Lint
              </h4>
              <div className="flex items-center gap-3">
                <span className={`text-2xl font-bold ${result.lint.ok ? "text-emerald-600" : "text-rose-600"}`}>
                  {result.lint.ok ? "Clean" : "Issues"}
                </span>
              </div>
              <div className="mt-2 flex gap-3 text-xs">
                <span className="text-rose-600">{result.lint.error_count} errors</span>
                <span className="text-amber-600">{result.lint.warning_count} warnings</span>
              </div>
              {result.lint.errors.length > 0 && (
                <ul className="mt-2 space-y-1">
                  {result.lint.errors.map((e, i) => (
                    <li key={i} className="rounded bg-rose-50 px-2 py-1 text-xs text-rose-700">
                      <span className="font-mono font-semibold">{e.code}</span>: {e.message}
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* Conflicts */}
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
              <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-2">
                Conflicts
              </h4>
              <div className="flex items-center gap-3">
                <span className={`text-2xl font-bold ${result.conflicts.ok ? "text-emerald-600" : "text-rose-600"}`}>
                  {result.conflicts.ok ? "None" : "Found"}
                </span>
              </div>
              <div className="mt-2 space-y-1 text-xs">
                <p>{result.conflicts.contradiction_count} contradictions</p>
                <p>{result.conflicts.shadowed_rule_count} shadowed rules</p>
                <p>{result.conflicts.coverage_gap_count} coverage gaps</p>
              </div>
            </div>

            {/* Simulation */}
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
              <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-2">
                Historical Impact
              </h4>
              {result.simulation ? (
                result.simulation.error ? (
                  <p className="text-xs text-amber-600">{result.simulation.error}</p>
                ) : (
                  <div className="space-y-1 text-xs">
                    <p>{result.simulation.scanned_events?.toLocaleString()} events scanned</p>
                    <p className="text-rose-600">
                      {result.simulation.would_block_count} would newly block
                    </p>
                    <p className="text-emerald-600">
                      {result.simulation.would_allow_count} would newly allow
                    </p>
                    {result.simulation.delta_breakdown && (
                      <div className="mt-1 flex h-2 overflow-hidden rounded-full bg-slate-100">
                        {result.simulation.delta_breakdown.allow_to_deny > 0 && (
                          <div
                            className="bg-rose-400"
                            style={{
                              width: `${
                                (result.simulation.delta_breakdown.allow_to_deny /
                                  Math.max(result.simulation.simulated_events ?? 1, 1)) *
                                100
                              }%`,
                            }}
                          />
                        )}
                        {result.simulation.delta_breakdown.deny_to_allow > 0 && (
                          <div
                            className="bg-emerald-400"
                            style={{
                              width: `${
                                (result.simulation.delta_breakdown.deny_to_allow /
                                  Math.max(result.simulation.simulated_events ?? 1, 1)) *
                                100
                              }%`,
                            }}
                          />
                        )}
                        <div className="flex-1 bg-slate-200" />
                      </div>
                    )}
                  </div>
                )
              ) : (
                <p className="text-xs text-slate-400 italic">Simulation skipped</p>
              )}
            </div>
          </div>

          {/* CLI usage hint */}
          <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
            <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-2">
              Use in CI Pipeline
            </h4>
            <pre className="text-xs font-mono text-slate-700 overflow-x-auto">{`# Add to your CI pipeline (GitHub Actions, GitLab CI, etc.)
curl -X POST https://app.releasegate.io/policies/ci/validate \\
  -H "Authorization: Bearer \$RELEASEGATE_API_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"policy_id": "${policyId || "<POLICY_ID>"}", "fail_on_warnings": ${failOnWarnings}}'

# Exit code: 0 if PASS, non-zero if FAIL
# Parse verdict from JSON response: .verdict == "PASS"`}</pre>
          </div>
        </div>
      )}
    </div>
  );
}
