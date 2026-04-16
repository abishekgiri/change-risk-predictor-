"use client";

import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { useState } from "react";
import { callDashboardApi } from "@/lib/api";

interface EvidenceItem {
  decision_id: string;
  created_at: string;
  status: string;
  repo: string;
  pr_number: number | null;
  policy_hash: string;
  actor: string | null;
  workflow_id: string | null;
  transition_id: string | null;
  has_approval: boolean;
  approval_count: number;
  signal_freshness: {
    stale: boolean | null;
    reason_code: string | null;
    age_seconds: number | null;
    computed_at: string | null;
  } | null;
  integrity: {
    decision_hash: string;
    input_hash: string;
    policy_hash: string;
    replay_hash: string;
  };
}

interface SearchResult {
  tenant_id: string;
  query: Record<string, unknown>;
  count: number;
  items: EvidenceItem[];
}

export function EvidenceSearchClient() {
  const searchParams = useSearchParams();
  const tenantId = searchParams.get("tenant_id") || "default";

  const [statusFilter, setStatusFilter] = useState("");
  const [approvalFilter, setApprovalFilter] = useState<"" | "true" | "false">("");
  const [actorFilter, setActorFilter] = useState("");
  const [workflowFilter, setWorkflowFilter] = useState("");
  const [days, setDays] = useState(30);
  const [result, setResult] = useState<SearchResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const search = async (overrides?: {
    status?: string;
    approval?: string;
    days?: number;
  }) => {
    const resolvedStatus = overrides?.status ?? statusFilter;
    const resolvedApproval = overrides?.approval ?? approvalFilter;
    const resolvedDays = overrides?.days ?? days;

    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      params.set("tenant_id", tenantId);
      params.set("days", String(resolvedDays));
      params.set("limit", "200");
      if (resolvedStatus) params.set("status", resolvedStatus);
      if (resolvedApproval) params.set("has_approval", resolvedApproval);
      if (actorFilter) params.set("actor", actorFilter);
      if (workflowFilter) params.set("workflow_id", workflowFilter);

      const data = await callDashboardApi<SearchResult>(
        `/api/dashboard/audit/evidence-search?${params.toString()}`,
      );
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
      <div>
        <Link
          href={`/audit?tenant_id=${encodeURIComponent(tenantId)}`}
          className="text-sm text-indigo-600 hover:text-indigo-800"
        >
          ← Back to Trust Overview
        </Link>
        <h1 className="mt-2 text-xl font-bold text-slate-900">Evidence Graph</h1>
        <p className="text-sm text-slate-500">
          Query decision history with structured proof. Every result includes integrity hashes.
        </p>
      </div>

      {/* Filters */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-4">
        <h3 className="text-sm font-semibold text-slate-800">Query Filters</h3>
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
          <label className="block">
            <span className="text-xs font-medium text-slate-600">Status</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
            >
              <option value="">All</option>
              <option value="ALLOWED">Allowed</option>
              <option value="BLOCKED">Blocked</option>
              <option value="CONDITIONAL">Conditional</option>
            </select>
          </label>
          <label className="block">
            <span className="text-xs font-medium text-slate-600">Has Approval</span>
            <select
              value={approvalFilter}
              onChange={(e) => setApprovalFilter(e.target.value as "" | "true" | "false")}
              className="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
            >
              <option value="">Any</option>
              <option value="true">With approval</option>
              <option value="false">Without approval</option>
            </select>
          </label>
          <label className="block">
            <span className="text-xs font-medium text-slate-600">Time Window</span>
            <select
              value={days}
              onChange={(e) => setDays(Number(e.target.value))}
              className="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
            >
              <option value={7}>Last 7 days</option>
              <option value={30}>Last 30 days</option>
              <option value={60}>Last 60 days</option>
              <option value={90}>Last 90 days</option>
            </select>
          </label>
          <label className="block">
            <span className="text-xs font-medium text-slate-600">Actor</span>
            <input
              type="text"
              value={actorFilter}
              onChange={(e) => setActorFilter(e.target.value)}
              placeholder="Optional"
              className="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
            />
          </label>
          <label className="block">
            <span className="text-xs font-medium text-slate-600">Workflow ID</span>
            <input
              type="text"
              value={workflowFilter}
              onChange={(e) => setWorkflowFilter(e.target.value)}
              placeholder="Optional"
              className="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
            />
          </label>
        </div>
        <button
          onClick={() => search()}
          disabled={loading}
          className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-60"
        >
          {loading ? "Searching..." : "Search Evidence"}
        </button>
      </div>

      {/* Preset queries */}
      <div className="flex flex-wrap gap-2">
        <span className="text-xs font-medium text-slate-500 self-center mr-1">Quick queries:</span>
        <button
          onClick={() => {
            setApprovalFilter("false");
            setStatusFilter("ALLOWED");
            setDays(30);
            search({ status: "ALLOWED", approval: "false", days: 30 });
          }}
          className="rounded-full border border-slate-300 bg-white px-3 py-1 text-xs text-slate-700 hover:bg-slate-50"
        >
          Releases without approval (30d)
        </button>
        <button
          onClick={() => {
            setStatusFilter("BLOCKED");
            setApprovalFilter("");
            setDays(30);
            search({ status: "BLOCKED", approval: "", days: 30 });
          }}
          className="rounded-full border border-slate-300 bg-white px-3 py-1 text-xs text-slate-700 hover:bg-slate-50"
        >
          All blocked decisions (30d)
        </button>
        <button
          onClick={() => {
            setStatusFilter("");
            setApprovalFilter("");
            setDays(7);
            search({ status: "", approval: "", days: 7 });
          }}
          className="rounded-full border border-slate-300 bg-white px-3 py-1 text-xs text-slate-700 hover:bg-slate-50"
        >
          All decisions (7d)
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
          <p className="text-sm text-slate-600">
            <span className="font-semibold">{result.count}</span> decision{result.count !== 1 ? "s" : ""} found
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
                    <th className="px-4 py-3">Decision</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Actor</th>
                    <th className="px-4 py-3">Approval</th>
                    <th className="px-4 py-3">Signal</th>
                    <th className="px-4 py-3">Time</th>
                    <th className="px-4 py-3">Integrity</th>
                  </tr>
                </thead>
                <tbody>
                  {result.items.map((item) => (
                    <tr key={item.decision_id} className="border-b border-slate-50 hover:bg-slate-50">
                      <td className="px-4 py-3">
                        <span className="font-mono text-xs text-indigo-600">
                          {item.decision_id.slice(0, 12)}
                        </span>
                        {item.repo && (
                          <p className="text-[10px] text-slate-400">{item.repo}</p>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-semibold ${
                          item.status === "ALLOWED"
                            ? "bg-emerald-50 text-emerald-700"
                            : item.status === "BLOCKED"
                              ? "bg-rose-50 text-rose-700"
                              : "bg-amber-50 text-amber-700"
                        }`}>
                          {item.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-600">
                        {item.actor || "—"}
                      </td>
                      <td className="px-4 py-3">
                        {item.has_approval ? (
                          <span className="text-xs text-emerald-600 font-semibold">
                            {item.approval_count} approval{item.approval_count !== 1 ? "s" : ""}
                          </span>
                        ) : (
                          <span className="text-xs text-rose-500 font-semibold">None</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        {item.signal_freshness === null ? (
                          <span className="text-xs text-slate-400">—</span>
                        ) : item.signal_freshness.stale ? (
                          <span
                            className="inline-flex rounded-full px-2 py-0.5 text-xs font-semibold bg-amber-50 text-amber-700"
                            title={item.signal_freshness.reason_code ?? "stale"}
                          >
                            Stale
                          </span>
                        ) : (
                          <span className="inline-flex rounded-full px-2 py-0.5 text-xs font-semibold bg-emerald-50 text-emerald-700">
                            Fresh
                          </span>
                        )}
                        {item.signal_freshness?.age_seconds != null && (
                          <p className="text-[10px] text-slate-400 mt-0.5">
                            {item.signal_freshness.age_seconds}s old
                          </p>
                        )}
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-500">
                        {new Date(item.created_at).toLocaleDateString("en-US", {
                          month: "short",
                          day: "numeric",
                          hour: "2-digit",
                          minute: "2-digit",
                        })}
                      </td>
                      <td className="px-4 py-3">
                        <details>
                          <summary className="cursor-pointer text-xs text-slate-500 hover:text-slate-700">
                            Hashes
                          </summary>
                          <div className="mt-1 space-y-0.5 font-mono text-[10px] text-slate-400">
                            <p>dec: {item.integrity.decision_hash?.slice(0, 16)}</p>
                            <p>inp: {item.integrity.input_hash?.slice(0, 16)}</p>
                            <p>pol: {item.integrity.policy_hash?.slice(0, 16)}</p>
                            <p>rep: {item.integrity.replay_hash?.slice(0, 16)}</p>
                          </div>
                        </details>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
