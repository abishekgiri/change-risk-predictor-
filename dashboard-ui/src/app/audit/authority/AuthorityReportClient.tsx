"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { callDashboardApi } from "@/lib/api";

interface VerificationResult {
  rg_decision_id: string;
  verified: boolean;
}

interface AuthorityReport {
  ok: boolean;
  tenant_id: string;
  generated_at: string;
  window_days: number;
  decisions: {
    total: number;
    covered_by_checkpoint: number;
    checkpoint_coverage_pct: number;
  };
  checkpoints: {
    total: number;
    externally_anchored: number;
    anchor_coverage_pct: number;
  };
  verification_sample: {
    checked: number;
    all_passed: boolean;
    results: VerificationResult[];
  };
  repo_coverage: Array<{ repo: string; decisions: number; blocked: number; allowed: number }>;
  authority_test: {
    passed: boolean;
    verdict: string;
  };
}

export function AuthorityReportClient() {
  const searchParams = useSearchParams();
  const tenantId = searchParams.get("tenant_id") || "";

  const [days, setDays] = useState(30);
  const [report, setReport] = useState<AuthorityReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (d: number) => {
    setLoading(true);
    setError(null);
    try {
      const data = await callDashboardApi<AuthorityReport>(
        `/api/dashboard/audit/authority-report?tenant_id=${encodeURIComponent(tenantId)}&days=${d}`
      );
      setReport(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load authority report");
    } finally {
      setLoading(false);
    }
  }, [tenantId]);

  useEffect(() => { load(days); }, [days, load]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <Link href={`/audit?tenant_id=${encodeURIComponent(tenantId)}`}
            className="text-sm text-indigo-600 hover:text-indigo-800">
            ← Trust & Audit
          </Link>
          <h1 className="mt-2 text-xl font-bold text-slate-900">Authority Report</h1>
          <p className="text-sm text-slate-500">
            Can ReleaseGate serve as the sole audit source for releases?
          </p>
        </div>
        <select value={days} onChange={(e) => setDays(Number(e.target.value))}
          className="rounded-md border border-slate-300 px-3 py-1.5 text-sm">
          <option value={7}>Last 7 days</option>
          <option value={30}>Last 30 days</option>
          <option value={90}>Last 90 days</option>
        </select>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">{error}</div>
      )}

      {loading && !report && (
        <div className="text-sm text-slate-400">Computing authority metrics…</div>
      )}

      {report && (
        <>
          {/* Authority verdict */}
          <div className={`rounded-xl border p-6 ${report.authority_test.passed ? "border-emerald-200 bg-emerald-50" : "border-amber-200 bg-amber-50"}`}>
            <div className="flex items-start gap-4">
              <span className="text-3xl">{report.authority_test.passed ? "🏛" : "⚠️"}</span>
              <div>
                <p className={`text-lg font-bold ${report.authority_test.passed ? "text-emerald-800" : "text-amber-800"}`}>
                  {report.authority_test.passed ? "Authority test PASSED" : "Authority test NOT YET PASSED"}
                </p>
                <p className="text-sm text-slate-600 mt-1">{report.authority_test.verdict}</p>
              </div>
            </div>
          </div>

          {/* Coverage metrics */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <CoverageCard
              label="Decision coverage"
              numerator={report.decisions.covered_by_checkpoint}
              denominator={report.decisions.total}
              pct={report.decisions.checkpoint_coverage_pct}
              target={80}
              sub="decisions inside a checkpoint"
            />
            <CoverageCard
              label="Anchor coverage"
              numerator={report.checkpoints.externally_anchored}
              denominator={report.checkpoints.total}
              pct={report.checkpoints.anchor_coverage_pct}
              target={50}
              sub="checkpoints with external anchor"
            />
            <div className={`rounded-xl border p-5 shadow-sm ${report.verification_sample.all_passed ? "border-emerald-200 bg-white" : "border-rose-200 bg-rose-50"}`}>
              <p className="text-xs font-medium text-slate-500 uppercase tracking-wide">Integrity sample</p>
              <p className={`mt-1 text-2xl font-bold ${report.verification_sample.all_passed ? "text-emerald-700" : "text-rose-700"}`}>
                {report.verification_sample.all_passed ? "All pass" : "FAILURES"}
              </p>
              <p className="mt-0.5 text-xs text-slate-400">
                {report.verification_sample.checked} recent decisions verified
              </p>
            </div>
          </div>

          {/* Verification sample detail */}
          {report.verification_sample.results.length > 0 && (
            <div className="rounded-xl border border-slate-200 bg-white shadow-sm">
              <div className="border-b border-slate-100 px-4 py-3">
                <h3 className="text-sm font-semibold text-slate-800">Replay Hash Verification Sample</h3>
                <p className="text-xs text-slate-500">
                  Each decision's replay_hash is recomputed from stored parts to detect tampering.
                </p>
              </div>
              <div className="divide-y divide-slate-50">
                {report.verification_sample.results.map((r) => (
                  <div key={r.rg_decision_id} className="flex items-center justify-between px-4 py-2.5">
                    <Link href={`/audit/trace/${encodeURIComponent(r.rg_decision_id)}?tenant_id=${encodeURIComponent(tenantId)}`}
                      className="font-mono text-xs text-indigo-600 hover:text-indigo-800">
                      {r.rg_decision_id}
                    </Link>
                    <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-semibold ${r.verified ? "bg-emerald-50 text-emerald-700" : "bg-rose-50 text-rose-700"}`}>
                      {r.verified ? "✓ Verified" : "✗ Mismatch"}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Per-repo coverage */}
          {report.repo_coverage.length > 0 && (
            <div className="rounded-xl border border-slate-200 bg-white shadow-sm">
              <div className="border-b border-slate-100 px-4 py-3">
                <h3 className="text-sm font-semibold text-slate-800">Per-Repository Coverage</h3>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-slate-100 text-left text-xs uppercase tracking-wide text-slate-500">
                      <th className="px-4 py-3">Repository</th>
                      <th className="px-4 py-3">Decisions</th>
                      <th className="px-4 py-3">Allowed</th>
                      <th className="px-4 py-3">Blocked</th>
                      <th className="px-4 py-3">Block rate</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.repo_coverage.map((r) => {
                      const rate = r.decisions > 0 ? Math.round(r.blocked / r.decisions * 100) : 0;
                      return (
                        <tr key={r.repo} className="border-b border-slate-50 hover:bg-slate-50">
                          <td className="px-4 py-3 font-mono text-xs text-slate-800">{r.repo}</td>
                          <td className="px-4 py-3 text-sm font-semibold">{r.decisions}</td>
                          <td className="px-4 py-3 text-sm text-emerald-600">{r.allowed}</td>
                          <td className="px-4 py-3 text-sm text-rose-600">{r.blocked}</td>
                          <td className="px-4 py-3">
                            <span className={`text-xs font-semibold ${rate > 20 ? "text-rose-600" : rate > 5 ? "text-amber-600" : "text-slate-500"}`}>
                              {rate}%
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          <p className="text-xs text-slate-400">
            Generated {new Date(report.generated_at).toLocaleString()} · {report.window_days}-day window
          </p>
        </>
      )}
    </div>
  );
}

function CoverageCard({ label, numerator, denominator, pct, target, sub }: {
  label: string; numerator: number; denominator: number; pct: number; target: number; sub: string;
}) {
  const ok = pct >= target;
  const warn = pct >= target * 0.6 && !ok;
  return (
    <div className={`rounded-xl border p-5 shadow-sm ${ok ? "border-emerald-200 bg-white" : warn ? "border-amber-200 bg-amber-50" : "border-rose-200 bg-rose-50"}`}>
      <p className="text-xs font-medium text-slate-500 uppercase tracking-wide">{label}</p>
      <p className={`mt-1 text-2xl font-bold ${ok ? "text-emerald-700" : warn ? "text-amber-700" : "text-rose-700"}`}>
        {pct}%
      </p>
      <p className="mt-0.5 text-xs text-slate-400">
        {numerator}/{denominator} {sub}
      </p>
      <div className="mt-2 h-1.5 w-full rounded-full bg-slate-100">
        <div
          className={`h-1.5 rounded-full ${ok ? "bg-emerald-500" : warn ? "bg-amber-500" : "bg-rose-500"}`}
          style={{ width: `${Math.min(pct, 100)}%` }}
        />
      </div>
    </div>
  );
}
