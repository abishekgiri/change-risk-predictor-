"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useState } from "react";
import { callDashboardApi } from "@/lib/api";

interface DecisionItem {
  rg_decision_id: string;
  decision_id: string;
  repo: string;
  pr_number: number | null;
  status: string;
  reason_code: string | null;
  actor: string | null;
  created_at: string;
  hashes: { input_hash: string; replay_hash: string };
}

interface DecisionList {
  tenant_id: string;
  count: number;
  window_days: number;
  items: DecisionItem[];
}

const STATUS_STYLES: Record<string, string> = {
  ALLOWED: "bg-emerald-50 text-emerald-700",
  BLOCKED: "bg-rose-50 text-rose-700",
  CONDITIONAL: "bg-amber-50 text-amber-700",
  SKIPPED: "bg-slate-100 text-slate-500",
};

export function DecisionRegistryClient() {
  const searchParams = useSearchParams();
  const tenantId = searchParams.get("tenant_id") || "default";

  const [repo, setRepo] = useState("");
  const [status, setStatus] = useState("");
  const [days, setDays] = useState(30);
  const [result, setResult] = useState<DecisionList | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const search = async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams({ tenant_id: tenantId, days: String(days), limit: "200" });
      if (repo.trim()) params.set("repo", repo.trim());
      if (status) params.set("status", status);
      const data = await callDashboardApi<DecisionList>(`/api/dashboard/decisions?${params}`);
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Search failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-900">Decision Registry</h1>
          <p className="text-sm text-slate-500">
            Every governed deploy decision — the authoritative record.{" "}
            <Link href={`/audit/authority?tenant_id=${encodeURIComponent(tenantId)}`}
              className="text-indigo-600 hover:text-indigo-800">
              Authority report →
            </Link>
          </p>
        </div>
      </div>

      {/* Filters */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-4">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <label className="block">
            <span className="text-xs font-medium text-slate-600">Repository</span>
            <input
              type="text"
              value={repo}
              onChange={(e) => setRepo(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && search()}
              placeholder="org/repo"
              className="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm font-mono"
            />
          </label>
          <label className="block">
            <span className="text-xs font-medium text-slate-600">Status</span>
            <select value={status} onChange={(e) => setStatus(e.target.value)}
              className="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm">
              <option value="">All</option>
              <option value="ALLOWED">Allowed</option>
              <option value="BLOCKED">Blocked</option>
              <option value="CONDITIONAL">Conditional</option>
            </select>
          </label>
          <label className="block">
            <span className="text-xs font-medium text-slate-600">Window</span>
            <select value={days} onChange={(e) => setDays(Number(e.target.value))}
              className="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm">
              <option value={7}>Last 7 days</option>
              <option value={30}>Last 30 days</option>
              <option value={90}>Last 90 days</option>
            </select>
          </label>
        </div>
        <button onClick={search} disabled={loading}
          className="rounded-lg bg-slate-900 px-5 py-2 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-60">
          {loading ? "Loading…" : "Search Decisions"}
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">{error}</div>
      )}

      {result && (
        <div className="space-y-3">
          <p className="text-sm text-slate-600">
            <span className="font-semibold">{result.count}</span> decision{result.count !== 1 ? "s" : ""} — {result.window_days}-day window
          </p>

          {result.items.length === 0 ? (
            <div className="rounded-xl border border-dashed border-slate-300 bg-slate-50 px-8 py-12 text-center">
              <p className="text-sm text-slate-500">No decisions match your query.</p>
            </div>
          ) : (
            <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-100 text-left text-xs uppercase tracking-wide text-slate-500">
                    <th className="px-4 py-3">Decision ID</th>
                    <th className="px-4 py-3">Repo</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Actor</th>
                    <th className="px-4 py-3">Time</th>
                    <th className="px-4 py-3">Integrity</th>
                    <th className="px-4 py-3">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {result.items.map((item) => (
                    <tr key={item.decision_id} className="border-b border-slate-50 hover:bg-slate-50">
                      <td className="px-4 py-3">
                        <Link href={`/audit/trace/${encodeURIComponent(item.rg_decision_id)}?tenant_id=${encodeURIComponent(tenantId)}`}
                          className="font-mono text-xs text-indigo-600 hover:text-indigo-800 font-semibold">
                          {item.rg_decision_id}
                        </Link>
                        {item.pr_number && (
                          <p className="text-[10px] text-slate-400">PR #{item.pr_number}</p>
                        )}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-700">{item.repo || "—"}</td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-semibold ${STATUS_STYLES[item.status] ?? "bg-slate-100 text-slate-600"}`}>
                          {item.status}
                        </span>
                        {item.reason_code && (
                          <p className="text-[10px] text-slate-400 mt-0.5">{item.reason_code}</p>
                        )}
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-600">{item.actor || "—"}</td>
                      <td className="px-4 py-3 text-xs text-slate-500">
                        {new Date(item.created_at).toLocaleDateString("en-US", {
                          month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
                        })}
                      </td>
                      <td className="px-4 py-3">
                        <details>
                          <summary className="cursor-pointer text-xs text-slate-400 hover:text-slate-600">Hashes</summary>
                          <div className="mt-1 font-mono text-[10px] text-slate-400 space-y-0.5">
                            <p>inp: {item.hashes.input_hash}</p>
                            <p>rep: {item.hashes.replay_hash}</p>
                          </div>
                        </details>
                      </td>
                      <td className="px-4 py-3">
                        <Link href={`/audit/trace/${encodeURIComponent(item.rg_decision_id)}?tenant_id=${encodeURIComponent(tenantId)}`}
                          className="text-xs text-indigo-600 hover:text-indigo-800">
                          Trace →
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* CLI hint */}
      <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
        <p className="text-xs font-semibold text-slate-700 mb-2">Declare a decision from CI/CD</p>
        <pre className="overflow-x-auto rounded-lg bg-slate-900 p-3 text-xs text-slate-200 font-mono">
{`curl -X POST "$RELEASEGATE_URL/decisions/declare" \\
  -H "Authorization: Bearer $RELEASEGATE_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"tenant_id":"${tenantId}","repo":"org/repo","environment":"PRODUCTION","sha":"$GIT_SHA"}'`}
        </pre>
      </div>
    </div>
  );
}
