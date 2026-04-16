import Link from "next/link";
import { backendFetch } from "@/lib/backend";
import { resolveDashboardScope, scopeToQuery } from "@/lib/dashboard-scope";
import type { RegistryPolicy } from "@/lib/types";
import { PolicyStatusBadge } from "@/components/PolicyStatusBadge";
import { ScopeBadge } from "@/components/ScopeBadge";
import { TraceInfo } from "@/components/TraceInfo";
import { PolicyDetailClient } from "./PolicyDetailClient";

export const dynamic = "force-dynamic";

export default async function PolicyDetailPage({
  params,
  searchParams,
}: {
  params: Promise<{ policyId: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { policyId } = await params;
  const sp = await searchParams;
  const scope = resolveDashboardScope(sp);
  const query = scopeToQuery(scope);

  let policy: RegistryPolicy | null = null;
  let fetchError: string | null = null;
  let traceId: string | null = null;

  try {
    const { data, traceId: tid } = await backendFetch<RegistryPolicy>(`/policies/${policyId}`, {
      method: "GET",
      query: { tenant_id: scope.tenantId },
    });
    policy = data;
    traceId = tid;
  } catch (err) {
    fetchError = err instanceof Error ? err.message : "Failed to load policy";
  }

  const scopedHref = (path: string) => {
    const q = query.toString();
    return q ? `${path}?${q}` : path;
  };

  if (fetchError || !policy) {
    return (
      <div className="space-y-4">
        <Link
          href={scopedHref("/policies")}
          className="text-sm text-indigo-600 hover:text-indigo-800"
        >
          ← Back to Registry
        </Link>
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
          {fetchError ?? "Policy not found"}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Breadcrumb */}
      <Link
        href={scopedHref("/policies")}
        className="text-sm text-indigo-600 hover:text-indigo-800"
      >
        ← Back to Registry
      </Link>

      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold text-slate-900 font-mono">
              {policy.policy_id.slice(0, 16)}...
            </h1>
            <PolicyStatusBadge status={policy.status} />
          </div>
          <div className="mt-1 flex items-center gap-3 text-sm text-slate-500">
            <ScopeBadge scopeType={policy.scope_type} scopeId={policy.scope_id} />
            <span>v{policy.version}</span>
            <span className="font-mono text-xs text-slate-400">
              hash: {policy.policy_hash.slice(0, 16)}
            </span>
          </div>
        </div>
        <Link
          href={scopedHref(`/policies/simulate?policy_id=${policyId}`)}
          className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50"
        >
          Simulate Impact
        </Link>
      </div>

      {/* Metadata grid */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <MetadataCard label="Created" value={formatDate(policy.created_at)} />
        <MetadataCard label="Created By" value={policy.created_by ?? "—"} />
        <MetadataCard label="Activated" value={formatDate(policy.activated_at)} />
        <MetadataCard
          label="Rollout"
          value={`${policy.rollout_percentage}%${policy.rollout_scope ? ` (${policy.rollout_scope})` : ""}`}
        />
      </div>

      {/* Client-side interactive sections */}
      <PolicyDetailClient
        policy={policy}
        tenantId={scope.tenantId ?? "default"}
      />

      {/* Policy JSON */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <h3 className="text-sm font-semibold text-slate-800 mb-3">Policy Definition (JSON)</h3>
        <pre className="max-h-96 overflow-auto rounded-lg bg-slate-50 p-4 text-xs font-mono text-slate-700 border border-slate-100">
          {JSON.stringify(policy.policy_json, null, 2)}
        </pre>
      </div>

      {traceId && (
        <details className="text-xs text-slate-400">
          <summary className="cursor-pointer">Debug</summary>
          <TraceInfo traceId={traceId} />
        </details>
      )}
    </div>
  );
}

function MetadataCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white px-4 py-3">
      <p className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-1 text-sm font-semibold text-slate-800 truncate">{value}</p>
    </div>
  );
}

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}
