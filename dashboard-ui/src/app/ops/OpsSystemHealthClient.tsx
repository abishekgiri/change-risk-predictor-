"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { callDashboardApi } from "@/lib/api";

interface DecisionStats {
  total: number;
  allowed: number;
  blocked: number;
  conditional: number;
  block_rate_pct: number;
}

interface CheckpointStats {
  tenants_with_checkpoint: number;
  all_active_tenants: number;
  coverage_pct: number;
}

interface AlertSummary {
  stale_signals: number;
  checkpoint_missed: number;
  deploy_blocked: number;
}

interface SystemHealth {
  ok: boolean;
  generated_at: string;
  window_hours: number;
  decisions: DecisionStats;
  checkpoints: CheckpointStats;
  alerts: AlertSummary;
  db: { ok: boolean };
}

const HOURS_OPTIONS = [
  { label: "Last 1h", value: 1 },
  { label: "Last 6h", value: 6 },
  { label: "Last 24h", value: 24 },
  { label: "Last 48h", value: 48 },
  { label: "Last 7d", value: 168 },
];

function StatusDot({ ok }: { ok: boolean }) {
  return (
    <span
      className={`inline-block h-2 w-2 rounded-full ${ok ? "bg-emerald-500" : "bg-rose-500"}`}
    />
  );
}

function MetricCard({
  label,
  value,
  sub,
  highlight,
}: {
  label: string;
  value: string | number;
  sub?: string;
  highlight?: "ok" | "warn" | "bad";
}) {
  const accent =
    highlight === "bad"
      ? "border-rose-200 bg-rose-50"
      : highlight === "warn"
        ? "border-amber-200 bg-amber-50"
        : "border-slate-200 bg-white";
  return (
    <div className={`rounded-xl border p-5 shadow-sm ${accent}`}>
      <p className="text-xs font-medium text-slate-500 uppercase tracking-wide">{label}</p>
      <p className="mt-1 text-2xl font-bold text-slate-900">{value}</p>
      {sub && <p className="mt-0.5 text-xs text-slate-400">{sub}</p>}
    </div>
  );
}

export function OpsSystemHealthClient() {
  const [hours, setHours] = useState(24);
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  const load = useCallback(
    async (h: number) => {
      setLoading(true);
      setError(null);
      try {
        const data = await callDashboardApi<SystemHealth>(
          `/api/dashboard/ops/system-health?hours=${h}`,
        );
        setHealth(data);
        setLastRefresh(new Date());
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load system health");
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  useEffect(() => {
    load(hours);
    // Auto-refresh every 60 seconds
    const interval = setInterval(() => load(hours), 60_000);
    return () => clearInterval(interval);
  }, [hours, load]);

  const totalAlerts = health
    ? health.alerts.stale_signals + health.alerts.checkpoint_missed + health.alerts.deploy_blocked
    : 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-slate-900">SRE System Health</h1>
          <p className="text-sm text-slate-500">
            Real-time governance engine status across all tenants.{" "}
            <Link href="/ops/tenant" className="text-indigo-600 hover:text-indigo-800">
              Per-tenant view →
            </Link>
          </p>
        </div>
        <div className="flex items-center gap-3">
          <select
            value={hours}
            onChange={(e) => setHours(Number(e.target.value))}
            className="rounded-md border border-slate-300 px-3 py-1.5 text-sm"
          >
            {HOURS_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
          <button
            onClick={() => load(hours)}
            disabled={loading}
            className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-60"
          >
            {loading ? "Refreshing…" : "Refresh"}
          </button>
        </div>
      </div>

      {lastRefresh && (
        <p className="text-xs text-slate-400">
          Last updated: {lastRefresh.toLocaleTimeString()} — auto-refreshes every 60s
        </p>
      )}

      {error && (
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
          {error}
        </div>
      )}

      {health && (
        <>
          {/* Status bar */}
          <div
            className={`flex items-center gap-3 rounded-xl border px-5 py-4 ${
              totalAlerts === 0
                ? "border-emerald-200 bg-emerald-50"
                : "border-amber-200 bg-amber-50"
            }`}
          >
            <StatusDot ok={totalAlerts === 0} />
            <div>
              <p className="text-sm font-semibold text-slate-900">
                {totalAlerts === 0
                  ? "All systems operational"
                  : `${totalAlerts} alert condition${totalAlerts !== 1 ? "s" : ""} active`}
              </p>
              <p className="text-xs text-slate-500">
                DB {health.db.ok ? "healthy" : "DEGRADED"} ·{" "}
                {health.decisions.total.toLocaleString()} decisions in window
              </p>
            </div>
          </div>

          {/* Decision metrics */}
          <section>
            <h2 className="mb-3 text-sm font-semibold text-slate-700 uppercase tracking-wide">
              Decisions ({HOURS_OPTIONS.find((o) => o.value === hours)?.label ?? `${hours}h`})
            </h2>
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <MetricCard label="Total" value={health.decisions.total.toLocaleString()} />
              <MetricCard
                label="Allowed"
                value={health.decisions.allowed.toLocaleString()}
                highlight="ok"
              />
              <MetricCard
                label="Blocked"
                value={health.decisions.blocked.toLocaleString()}
                highlight={health.decisions.blocked > 0 ? "warn" : undefined}
              />
              <MetricCard
                label="Block rate"
                value={`${health.decisions.block_rate_pct}%`}
                sub="of decisions blocked"
                highlight={
                  health.decisions.block_rate_pct > 20
                    ? "bad"
                    : health.decisions.block_rate_pct > 5
                      ? "warn"
                      : undefined
                }
              />
            </div>
          </section>

          {/* Checkpoint coverage */}
          <section>
            <h2 className="mb-3 text-sm font-semibold text-slate-700 uppercase tracking-wide">
              Audit Checkpoints
            </h2>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
              <MetricCard
                label="Coverage"
                value={`${health.checkpoints.coverage_pct}%`}
                sub="tenants with recent checkpoint"
                highlight={
                  health.checkpoints.coverage_pct < 80
                    ? "bad"
                    : health.checkpoints.coverage_pct < 95
                      ? "warn"
                      : "ok"
                }
              />
              <MetricCard
                label="Active tenants"
                value={health.checkpoints.all_active_tenants}
              />
              <MetricCard
                label="Checkpointed"
                value={health.checkpoints.tenants_with_checkpoint}
                sub={`in last ${hours}h`}
              />
            </div>
          </section>

          {/* Alert conditions */}
          <section>
            <h2 className="mb-3 text-sm font-semibold text-slate-700 uppercase tracking-wide">
              Alert Conditions
            </h2>
            <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-100 text-left text-xs uppercase tracking-wide text-slate-500">
                    <th className="px-4 py-3">Condition</th>
                    <th className="px-4 py-3">Tenants affected</th>
                    <th className="px-4 py-3">Severity</th>
                    <th className="px-4 py-3">Action</th>
                  </tr>
                </thead>
                <tbody>
                  <AlertRow
                    label="Stale signal"
                    count={health.alerts.stale_signals}
                    severity="warning"
                    action="Check signal pipeline"
                  />
                  <AlertRow
                    label="Checkpoint missed"
                    count={health.alerts.checkpoint_missed}
                    severity="critical"
                    action="Run manual checkpoint"
                  />
                  <AlertRow
                    label="Deploy blocked"
                    count={health.alerts.deploy_blocked}
                    severity="warning"
                    action="Review /audit/evidence"
                  />
                </tbody>
              </table>
            </div>
          </section>

          {/* DB health */}
          <section>
            <h2 className="mb-3 text-sm font-semibold text-slate-700 uppercase tracking-wide">
              Infrastructure
            </h2>
            <div className="flex items-center gap-3 rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <StatusDot ok={health.db.ok} />
              <div>
                <p className="text-sm font-semibold text-slate-800">
                  Database {health.db.ok ? "healthy" : "DEGRADED"}
                </p>
                <p className="text-xs text-slate-500">Storage backend responding normally</p>
              </div>
            </div>
          </section>

          <p className="text-xs text-slate-400">
            Generated at {new Date(health.generated_at).toLocaleString()} · {hours}h window
          </p>
        </>
      )}
    </div>
  );
}

function AlertRow({
  label,
  count,
  severity,
  action,
}: {
  label: string;
  count: number;
  severity: "warning" | "critical";
  action: string;
}) {
  return (
    <tr className="border-b border-slate-50 last:border-0">
      <td className="px-4 py-3 text-sm font-medium text-slate-800">{label}</td>
      <td className="px-4 py-3">
        {count === 0 ? (
          <span className="inline-flex rounded-full bg-emerald-50 px-2 py-0.5 text-xs font-semibold text-emerald-700">
            None
          </span>
        ) : (
          <span
            className={`inline-flex rounded-full px-2 py-0.5 text-xs font-semibold ${
              severity === "critical"
                ? "bg-rose-50 text-rose-700"
                : "bg-amber-50 text-amber-700"
            }`}
          >
            {count}
          </span>
        )}
      </td>
      <td className="px-4 py-3">
        <span
          className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${
            severity === "critical"
              ? "bg-rose-100 text-rose-600"
              : "bg-amber-100 text-amber-600"
          }`}
        >
          {severity}
        </span>
      </td>
      <td className="px-4 py-3 text-xs text-slate-500">{action}</td>
    </tr>
  );
}
