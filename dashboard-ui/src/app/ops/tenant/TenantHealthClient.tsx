"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useCallback, useState } from "react";
import { callDashboardApi } from "@/lib/api";

interface SignalStatus {
  ok: boolean;
  age_hours: number | null;
}

interface CheckpointStatus {
  ok: boolean;
  age_hours: number | null;
}

interface ChainStatus {
  ok: boolean;
}

interface TenantHealth {
  ok: boolean;
  tenant_id: string;
  generated_at: string;
  safe_to_deploy: boolean;
  issues: string[];
  warnings: string[];
  signal: SignalStatus;
  checkpoint: CheckpointStatus;
  chain: ChainStatus;
  blocked_last_hour: number;
  open_overrides: number;
}

function SafetyBadge({ safe }: { safe: boolean }) {
  return safe ? (
    <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-50 px-3 py-1 text-sm font-semibold text-emerald-700 border border-emerald-200">
      <span className="h-2 w-2 rounded-full bg-emerald-500" />
      Safe to deploy
    </span>
  ) : (
    <span className="inline-flex items-center gap-1.5 rounded-full bg-rose-50 px-3 py-1 text-sm font-semibold text-rose-700 border border-rose-200">
      <span className="h-2 w-2 rounded-full bg-rose-500" />
      Deploy blocked
    </span>
  );
}

function CheckRow({
  label,
  ok,
  detail,
}: {
  label: string;
  ok: boolean;
  detail?: string;
}) {
  return (
    <div className="flex items-start gap-3 py-3 border-b border-slate-50 last:border-0">
      <span
        className={`mt-0.5 h-4 w-4 flex-shrink-0 rounded-full flex items-center justify-center text-[10px] font-bold ${
          ok ? "bg-emerald-100 text-emerald-700" : "bg-rose-100 text-rose-700"
        }`}
      >
        {ok ? "✓" : "✗"}
      </span>
      <div>
        <p className="text-sm font-medium text-slate-800">{label}</p>
        {detail && <p className="text-xs text-slate-500">{detail}</p>}
      </div>
    </div>
  );
}

export function TenantHealthClient() {
  const searchParams = useSearchParams();
  const defaultTenant = searchParams.get("tenant_id") || "";

  const [tenantInput, setTenantInput] = useState(defaultTenant);
  const [health, setHealth] = useState<TenantHealth | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const check = useCallback(async (tid: string) => {
    const t = tid.trim();
    if (!t) return;
    setLoading(true);
    setError(null);
    try {
      const data = await callDashboardApi<TenantHealth>(
        `/api/dashboard/ops/tenant-health/${encodeURIComponent(t)}`,
      );
      setHealth(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Health check failed");
    } finally {
      setLoading(false);
    }
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <Link
          href="/ops"
          className="text-sm text-indigo-600 hover:text-indigo-800"
        >
          ← System Health
        </Link>
        <h1 className="mt-2 text-xl font-bold text-slate-900">Tenant Safety Check</h1>
        <p className="text-sm text-slate-500">
          Per-tenant deployment safety: signal freshness, checkpoint status, chain integrity, and
          open exceptions.
        </p>
      </div>

      {/* Tenant picker */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex gap-3">
          <input
            type="text"
            value={tenantInput}
            onChange={(e) => setTenantInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && check(tenantInput)}
            placeholder="Enter tenant ID…"
            className="flex-1 rounded-md border border-slate-300 px-3 py-2 text-sm font-mono"
          />
          <button
            onClick={() => check(tenantInput)}
            disabled={loading || !tenantInput.trim()}
            className="rounded-lg bg-slate-900 px-5 py-2 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-60"
          >
            {loading ? "Checking…" : "Check"}
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
          {error}
        </div>
      )}

      {health && (
        <div className="space-y-4">
          {/* Safety verdict */}
          <div
            className={`rounded-xl border p-6 ${
              health.safe_to_deploy
                ? "border-emerald-200 bg-emerald-50"
                : "border-rose-200 bg-rose-50"
            }`}
          >
            <div className="flex items-start justify-between flex-wrap gap-4">
              <div>
                <p className="text-xs font-medium text-slate-500 mb-1">
                  Tenant: <span className="font-mono font-semibold text-slate-800">{health.tenant_id}</span>
                </p>
                <SafetyBadge safe={health.safe_to_deploy} />
              </div>
              <div className="text-right">
                <p className="text-xs text-slate-400">
                  Checked {new Date(health.generated_at).toLocaleTimeString()}
                </p>
              </div>
            </div>

            {health.issues.length > 0 && (
              <div className="mt-4 space-y-1">
                {health.issues.map((issue) => (
                  <div key={issue} className="flex items-start gap-2 text-sm text-rose-700">
                    <span className="mt-0.5 font-bold">•</span>
                    {issue}
                  </div>
                ))}
              </div>
            )}
            {health.warnings.length > 0 && (
              <div className="mt-3 space-y-1">
                {health.warnings.map((w) => (
                  <div key={w} className="flex items-start gap-2 text-sm text-amber-700">
                    <span className="mt-0.5 font-bold">!</span>
                    {w}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Check breakdown */}
          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <h2 className="mb-1 text-sm font-semibold text-slate-800">Safety Checks</h2>
            <CheckRow
              label="Risk signal freshness"
              ok={health.signal.ok}
              detail={
                health.signal.age_hours != null
                  ? `Last signal ${health.signal.age_hours.toFixed(1)}h ago`
                  : "No signals found"
              }
            />
            <CheckRow
              label="Signed checkpoint"
              ok={health.checkpoint.ok}
              detail={
                health.checkpoint.age_hours != null
                  ? `Last checkpoint ${health.checkpoint.age_hours.toFixed(1)}h ago`
                  : "No checkpoints found"
              }
            />
            <CheckRow
              label="Override chain integrity"
              ok={health.chain.ok}
              detail="Hash chain verified against ledger"
            />
          </div>

          {/* Stats row */}
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <p className="text-xs font-medium text-slate-500 uppercase tracking-wide">
                Blocked (1h)
              </p>
              <p
                className={`mt-1 text-2xl font-bold ${
                  health.blocked_last_hour > 0 ? "text-amber-600" : "text-slate-900"
                }`}
              >
                {health.blocked_last_hour}
              </p>
            </div>
            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <p className="text-xs font-medium text-slate-500 uppercase tracking-wide">
                Open overrides
              </p>
              <p
                className={`mt-1 text-2xl font-bold ${
                  health.open_overrides > 5 ? "text-amber-600" : "text-slate-900"
                }`}
              >
                {health.open_overrides}
              </p>
            </div>
            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <p className="text-xs font-medium text-slate-500 uppercase tracking-wide">
                Chain
              </p>
              <p
                className={`mt-1 text-2xl font-bold ${
                  health.chain.ok ? "text-emerald-600" : "text-rose-600"
                }`}
              >
                {health.chain.ok ? "Valid" : "Broken"}
              </p>
            </div>
          </div>

          {/* Deep links */}
          <div className="flex flex-wrap gap-3 text-sm">
            <Link
              href={`/audit?tenant_id=${encodeURIComponent(health.tenant_id)}`}
              className="rounded-lg border border-indigo-200 bg-indigo-50 px-4 py-2 text-indigo-700 hover:bg-indigo-100"
            >
              Trust & Audit →
            </Link>
            <Link
              href={`/audit/evidence?tenant_id=${encodeURIComponent(health.tenant_id)}`}
              className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-slate-700 hover:bg-slate-50"
            >
              Evidence Graph →
            </Link>
            <Link
              href={`/integrity?tenant_id=${encodeURIComponent(health.tenant_id)}`}
              className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-slate-700 hover:bg-slate-50"
            >
              Control Health →
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}
