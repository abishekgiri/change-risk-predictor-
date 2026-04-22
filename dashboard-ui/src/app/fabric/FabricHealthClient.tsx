"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { callDashboardApi } from "@/lib/api";

interface CompletenessHealth {
  pct: number;
  fully_linked: number;
  verdict: "HEALTHY" | "DEGRADED" | "CRITICAL";
}

interface IntegrityHealth {
  orphan_deploys: number;
  broken_chains: number;
  verdict: "OK" | "WARNING" | "CRITICAL";
}

interface FrictionHealth {
  block_rate_pct: number;
  override_count: number;
  verdict: "LOW" | "MEDIUM" | "HIGH";
}

interface FabricHealth {
  ok: boolean;
  tenant_id: string;
  window_days: number;
  total_changes: number;
  by_state: Record<string, number>;
  deployed_count: number;
  blocked_count: number;
  incident_count: number;
  // 3-dimensional health (new)
  completeness?: CompletenessHealth;
  integrity?: IntegrityHealth;
  friction?: FrictionHealth;
  // legacy flat fields (kept for backward compat)
  orphan_deploys?: number;
  coverage_pct?: number;
  block_rate_pct?: number;
  health_verdict: "HEALTHY" | "DEGRADED" | "CRITICAL";
}

interface ChangeItem {
  change_id: string;
  lifecycle_state: string;
  jira_issue_key: string | null;
  pr_repo: string | null;
  deploy_id: string | null;
  incident_id: string | null;
  environment: string | null;
  actor: string | null;
  missing_links: string[];
  violation_codes: string[];
  created_at: string;
  updated_at: string;
}

interface ChangeList {
  tenant_id: string;
  count: number;
  items: ChangeItem[];
}

const STATE_STYLES: Record<string, string> = {
  CREATED:            "bg-slate-100 text-slate-600",
  LINKED:             "bg-blue-50 text-blue-700",
  APPROVED:           "bg-indigo-50 text-indigo-700",
  DEPLOYED:           "bg-emerald-50 text-emerald-700",
  INCIDENT_ACTIVE:    "bg-rose-50 text-rose-700",
  HOTFIX_IN_PROGRESS: "bg-amber-50 text-amber-700",
  VERIFIED:           "bg-teal-50 text-teal-700",
  CLOSED:             "bg-slate-100 text-slate-500",
  BLOCKED:            "bg-rose-100 text-rose-800",
};

const VERDICT_STYLES = {
  HEALTHY:  "border-emerald-200 bg-emerald-50 text-emerald-800",
  DEGRADED: "border-amber-200 bg-amber-50 text-amber-800",
  CRITICAL: "border-rose-200 bg-rose-50 text-rose-800",
};

const VERDICT_ICONS = { HEALTHY: "✓", DEGRADED: "⚠", CRITICAL: "✗" };

export function FabricHealthClient() {
  const searchParams = useSearchParams();
  const tenantId = searchParams.get("tenant_id") || "";

  const [days, setDays] = useState(30);
  const [stateFilter, setStateFilter] = useState("");
  const [health, setHealth] = useState<FabricHealth | null>(null);
  const [changes, setChanges] = useState<ChangeList | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [h, c] = await Promise.all([
        callDashboardApi<FabricHealth>(
          `/api/dashboard/fabric/health?tenant_id=${encodeURIComponent(tenantId)}&days=${days}`
        ),
        callDashboardApi<ChangeList>(
          `/api/dashboard/fabric/changes?tenant_id=${encodeURIComponent(tenantId)}&limit=100${stateFilter ? `&lifecycle_state=${stateFilter}` : ""}`
        ),
      ]);
      setHealth(h);
      setChanges(c);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load fabric data");
    } finally {
      setLoading(false);
    }
  }, [tenantId, days, stateFilter]);

  useEffect(() => { load(); }, [load]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-slate-900">Cross-System Governance Fabric</h1>
          <p className="text-sm text-slate-500 mt-0.5">
            Every change traced from Jira → PR → Decision → Deploy → Incident → Hotfix.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <select value={days} onChange={(e) => setDays(Number(e.target.value))}
            className="rounded-md border border-slate-300 px-3 py-1.5 text-sm">
            <option value={7}>Last 7 days</option>
            <option value={30}>Last 30 days</option>
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

      {/* Health verdict */}
      {health && (
        <>
          <div className={`rounded-xl border p-5 ${VERDICT_STYLES[health.health_verdict]}`}>
            <div className="flex items-center gap-3">
              <span className="text-2xl font-bold">{VERDICT_ICONS[health.health_verdict]}</span>
              <div>
                <p className="text-base font-bold">{health.health_verdict}</p>
                <p className="text-sm opacity-80">
                  {health.orphan_deploys === 0
                    ? "All deploys are fully linked across systems."
                    : `${health.orphan_deploys} orphan deploy${health.orphan_deploys !== 1 ? "s" : ""} detected — missing PR or Jira linkage.`}
                </p>
              </div>
            </div>
          </div>

          {/* 3-Dimensional Health Cards */}
          {(health.completeness || health.integrity || health.friction) && (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
              {health.completeness && (() => {
                const v = health.completeness.verdict;
                const style = v === "HEALTHY" ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                  : v === "DEGRADED" ? "border-amber-200 bg-amber-50 text-amber-800"
                  : "border-rose-200 bg-rose-50 text-rose-800";
                return (
                  <div className={`rounded-xl border p-5 shadow-sm ${style}`}>
                    <p className="text-xs font-semibold uppercase tracking-wide opacity-70">Completeness</p>
                    <p className="mt-1 text-3xl font-bold">{health.completeness.pct}%</p>
                    <p className="mt-0.5 text-sm font-medium">{v}</p>
                    <p className="mt-1 text-xs opacity-70">{health.completeness.fully_linked} fully-linked changes</p>
                  </div>
                );
              })()}
              {health.integrity && (() => {
                const v = health.integrity.verdict;
                const style = v === "OK" ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                  : v === "WARNING" ? "border-amber-200 bg-amber-50 text-amber-800"
                  : "border-rose-200 bg-rose-50 text-rose-800";
                return (
                  <div className={`rounded-xl border p-5 shadow-sm ${style}`}>
                    <p className="text-xs font-semibold uppercase tracking-wide opacity-70">Integrity</p>
                    <p className="mt-1 text-3xl font-bold">{health.integrity.orphan_deploys}</p>
                    <p className="mt-0.5 text-sm font-medium">{v} — orphan deploys</p>
                    <p className="mt-1 text-xs opacity-70">{health.integrity.broken_chains} broken chain{health.integrity.broken_chains !== 1 ? "s" : ""}</p>
                  </div>
                );
              })()}
              {health.friction && (() => {
                const v = health.friction.verdict;
                const style = v === "LOW" ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                  : v === "MEDIUM" ? "border-amber-200 bg-amber-50 text-amber-800"
                  : "border-rose-200 bg-rose-50 text-rose-800";
                return (
                  <div className={`rounded-xl border p-5 shadow-sm ${style}`}>
                    <p className="text-xs font-semibold uppercase tracking-wide opacity-70">Friction</p>
                    <p className="mt-1 text-3xl font-bold">{health.friction.block_rate_pct}%</p>
                    <p className="mt-0.5 text-sm font-medium">{v} — block rate</p>
                    <p className="mt-1 text-xs opacity-70">{health.friction.override_count} override{health.friction.override_count !== 1 ? "s" : ""}</p>
                  </div>
                );
              })()}
            </div>
          )}

          {/* Summary counts */}
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            {[
              { label: "Total changes", value: health.total_changes,  sub: `${health.window_days}-day window` },
              { label: "Deployed",      value: health.deployed_count, sub: "deploy_id recorded" },
              { label: "Blocked",       value: health.blocked_count,  sub: "enforcement violations", alert: health.blocked_count > 0 },
              { label: "Incidents",     value: health.incident_count, sub: "linked to deploys",      alert: health.incident_count > 0 },
            ].map(({ label, value, sub, alert }) => (
              <div key={label} className={`rounded-xl border p-5 shadow-sm ${alert ? "border-amber-200 bg-amber-50" : "border-slate-200 bg-white"}`}>
                <p className="text-xs font-medium text-slate-500 uppercase tracking-wide">{label}</p>
                <p className={`mt-1 text-2xl font-bold ${alert ? "text-amber-700" : "text-slate-900"}`}>{value}</p>
                <p className="mt-0.5 text-xs text-slate-400">{sub}</p>
              </div>
            ))}
          </div>

          {/* State breakdown */}
          <div className="rounded-xl border border-slate-200 bg-white shadow-sm">
            <div className="border-b border-slate-100 px-4 py-3">
              <h3 className="text-sm font-semibold text-slate-800">Lifecycle State Breakdown</h3>
            </div>
            <div className="flex flex-wrap gap-2 p-4">
              {Object.entries(health.by_state).map(([state, count]) => (
                <span key={state}
                  className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-semibold cursor-pointer
                    ${stateFilter === state ? "ring-2 ring-slate-400" : ""} ${STATE_STYLES[state] ?? "bg-slate-100 text-slate-600"}`}
                  onClick={() => setStateFilter(stateFilter === state ? "" : state)}>
                  {state} <span className="font-bold">{count}</span>
                </span>
              ))}
              {stateFilter && (
                <span className="inline-flex items-center gap-1 rounded-full border border-slate-300 px-3 py-1 text-xs text-slate-500 cursor-pointer hover:bg-slate-50"
                  onClick={() => setStateFilter("")}>
                  ✕ clear filter
                </span>
              )}
            </div>
          </div>
        </>
      )}

      {/* Change list */}
      {changes && (
        <div className="rounded-xl border border-slate-200 bg-white shadow-sm">
          <div className="border-b border-slate-100 px-4 py-3 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-800">
              Change Records
              {stateFilter && <span className="ml-2 text-xs text-slate-400">({stateFilter})</span>}
            </h3>
            <span className="text-xs text-slate-400">{changes.count} records</span>
          </div>
          {changes.items.length === 0 ? (
            <div className="px-8 py-12 text-center text-sm text-slate-400">No change records found.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-100 text-left text-xs uppercase tracking-wide text-slate-500">
                    <th className="px-4 py-3">Change ID</th>
                    <th className="px-4 py-3">State</th>
                    <th className="px-4 py-3">Jira</th>
                    <th className="px-4 py-3">Repo</th>
                    <th className="px-4 py-3">Environment</th>
                    <th className="px-4 py-3">Violations</th>
                    <th className="px-4 py-3">Updated</th>
                    <th className="px-4 py-3"></th>
                  </tr>
                </thead>
                <tbody>
                  {changes.items.map((item) => (
                    <tr key={item.change_id} className="border-b border-slate-50 hover:bg-slate-50">
                      <td className="px-4 py-3">
                        <Link href={`/fabric/${encodeURIComponent(item.change_id)}?tenant_id=${encodeURIComponent(tenantId)}`}
                          className="font-mono text-xs text-indigo-600 hover:text-indigo-800 font-semibold">
                          {item.change_id}
                        </Link>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-semibold ${STATE_STYLES[item.lifecycle_state] ?? "bg-slate-100 text-slate-600"}`}>
                          {item.lifecycle_state}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs font-mono text-slate-600">{item.jira_issue_key || "—"}</td>
                      <td className="px-4 py-3 text-xs font-mono text-slate-600">{item.pr_repo || "—"}</td>
                      <td className="px-4 py-3 text-xs text-slate-500">{item.environment || "—"}</td>
                      <td className="px-4 py-3">
                        {item.violation_codes.length > 0 ? (
                          <span className="text-xs text-rose-600 font-medium">{item.violation_codes.length} violation{item.violation_codes.length !== 1 ? "s" : ""}</span>
                        ) : (
                          <span className="text-xs text-emerald-600">✓ clean</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-400">
                        {new Date(item.updated_at).toLocaleDateString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
                      </td>
                      <td className="px-4 py-3">
                        <Link href={`/fabric/${encodeURIComponent(item.change_id)}?tenant_id=${encodeURIComponent(tenantId)}`}
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
        <p className="text-xs font-semibold text-slate-700 mb-2">Open a change from CI/CD</p>
        <pre className="overflow-x-auto rounded-lg bg-slate-900 p-3 text-xs text-slate-200 font-mono">
{`curl -X POST "$RELEASEGATE_URL/fabric/changes" \\
  -H "Authorization: Bearer $RELEASEGATE_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"tenant_id":"${tenantId}","environment":"PRODUCTION","jira_issue_key":"PROJ-42","pr_repo":"org/repo","pr_sha":"$GIT_SHA"}'`}
        </pre>
      </div>
    </div>
  );
}
