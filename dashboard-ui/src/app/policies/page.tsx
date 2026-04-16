import Link from "next/link";
import { backendFetch } from "@/lib/backend";
import { resolveDashboardScope, scopeToQuery } from "@/lib/dashboard-scope";
import type { PolicyListResponse, RegistryPolicy, PolicyStatus, PolicyScopeType } from "@/lib/types";
import { PolicyStatusBadge } from "@/components/PolicyStatusBadge";
import { ScopeBadge } from "@/components/ScopeBadge";
import { TraceInfo } from "@/components/TraceInfo";

export const dynamic = "force-dynamic";

function lintSummary(policy: RegistryPolicy) {
  const errs = policy.lint_errors?.length ?? 0;
  const warns = policy.lint_warnings?.length ?? 0;
  if (errs > 0) return { text: `${errs} error${errs > 1 ? "s" : ""}`, color: "text-rose-600" };
  if (warns > 0) return { text: `${warns} warn`, color: "text-amber-600" };
  return { text: "Clean", color: "text-emerald-600" };
}

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

export default async function PoliciesPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;
  const scope = resolveDashboardScope(params);
  const query = scopeToQuery(scope);

  const statusFilter = typeof params.status === "string" ? params.status : undefined;
  const scopeTypeFilter = typeof params.scope_type === "string" ? params.scope_type : undefined;

  let policies: RegistryPolicy[] = [];
  let traceId: string | null = null;
  let fetchError: string | null = null;

  try {
    const { data, traceId: tid } = await backendFetch<PolicyListResponse>("/policies", {
      method: "GET",
      query: {
        tenant_id: scope.tenantId,
        status: statusFilter,
        scope_type: scopeTypeFilter,
        limit: 200,
      },
    });
    policies = data.policies ?? [];
    traceId = tid;
  } catch (err) {
    fetchError = err instanceof Error ? err.message : "Failed to load policies";
  }

  const scopedHref = (path: string) => {
    const q = query.toString();
    return q ? `${path}?${q}` : path;
  };

  // Group counts for filter chips
  const statusCounts: Record<string, number> = {};
  const scopeCounts: Record<string, number> = {};
  for (const p of policies) {
    statusCounts[p.status] = (statusCounts[p.status] ?? 0) + 1;
    scopeCounts[p.scope_type] = (scopeCounts[p.scope_type] ?? 0) + 1;
  }

  const allStatuses: PolicyStatus[] = ["ACTIVE", "STAGED", "DRAFT", "ARCHIVED", "DEPRECATED"];
  const allScopes: PolicyScopeType[] = ["org", "project", "workflow", "transition"];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-900">Policy Registry</h1>
          <p className="text-sm text-slate-500">
            {policies.length} polic{policies.length !== 1 ? "ies" : "y"} across all scopes
          </p>
        </div>
        <div className="flex gap-2">
          <Link
            href={scopedHref("/policies/simulate")}
            className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50"
          >
            Simulate Impact
          </Link>
          <Link
            href={scopedHref("/policies/create")}
            className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800"
          >
            Create Policy
          </Link>
        </div>
      </div>

      {/* Filter chips */}
      <div className="flex flex-wrap gap-4">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-xs font-medium uppercase tracking-wide text-slate-500 mr-1">Status</span>
          {allStatuses.map((s) => {
            const count = statusCounts[s] ?? 0;
            const isActive = statusFilter === s;
            return (
              <Link
                key={s}
                href={scopedHref(`/policies${isActive ? "" : `?status=${s}`}`)}
                className={`rounded-full px-2.5 py-0.5 text-xs font-medium border ${
                  isActive
                    ? "bg-slate-900 text-white border-slate-900"
                    : count > 0
                      ? "bg-white text-slate-700 border-slate-300 hover:bg-slate-50"
                      : "bg-white text-slate-400 border-slate-200"
                }`}
              >
                {s} ({count})
              </Link>
            );
          })}
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-xs font-medium uppercase tracking-wide text-slate-500 mr-1">Scope</span>
          {allScopes.map((s) => {
            const count = scopeCounts[s] ?? 0;
            const isActive = scopeTypeFilter === s;
            return (
              <Link
                key={s}
                href={scopedHref(`/policies${isActive ? "" : `?scope_type=${s}`}`)}
                className={`rounded-full px-2.5 py-0.5 text-xs font-medium border ${
                  isActive
                    ? "bg-slate-900 text-white border-slate-900"
                    : count > 0
                      ? "bg-white text-slate-700 border-slate-300 hover:bg-slate-50"
                      : "bg-white text-slate-400 border-slate-200"
                }`}
              >
                {s} ({count})
              </Link>
            );
          })}
        </div>
      </div>

      {/* Error state */}
      {fetchError && (
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
          {fetchError}
        </div>
      )}

      {/* Empty state */}
      {!fetchError && policies.length === 0 && (
        <div className="rounded-xl border border-dashed border-slate-300 bg-slate-50 px-8 py-12 text-center">
          <p className="text-lg font-semibold text-slate-700">No policies yet</p>
          <p className="mt-1 text-sm text-slate-500">
            Create your first policy to start governing releases.
          </p>
          <Link
            href={scopedHref("/policies/create")}
            className="mt-4 inline-block rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800"
          >
            Create Policy
          </Link>
        </div>
      )}

      {/* Policy table */}
      {policies.length > 0 && (
        <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-100 text-left text-xs uppercase tracking-wide text-slate-500">
                <th className="px-4 py-3">Policy</th>
                <th className="px-4 py-3">Scope</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Version</th>
                <th className="px-4 py-3">Lint</th>
                <th className="px-4 py-3">Rollout</th>
                <th className="px-4 py-3">Created</th>
              </tr>
            </thead>
            <tbody>
              {policies.map((policy) => {
                const lint = lintSummary(policy);
                return (
                  <tr
                    key={policy.policy_id}
                    className="border-b border-slate-50 hover:bg-slate-50 transition-colors"
                  >
                    <td className="px-4 py-3">
                      <Link
                        href={scopedHref(`/policies/${policy.policy_id}`)}
                        className="font-medium text-indigo-600 hover:text-indigo-800"
                      >
                        <span className="font-mono text-xs">{policy.policy_id.slice(0, 12)}</span>
                      </Link>
                      <p className="text-[10px] font-mono text-slate-400 mt-0.5">
                        {policy.policy_hash.slice(0, 16)}
                      </p>
                    </td>
                    <td className="px-4 py-3">
                      <ScopeBadge scopeType={policy.scope_type} scopeId={policy.scope_id} />
                    </td>
                    <td className="px-4 py-3">
                      <PolicyStatusBadge status={policy.status} />
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-600">v{policy.version}</td>
                    <td className="px-4 py-3">
                      <span className={`text-xs font-semibold ${lint.color}`}>
                        {lint.text}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <div className="h-1.5 w-16 overflow-hidden rounded-full bg-slate-100">
                          <div
                            className="h-full rounded-full bg-emerald-400"
                            style={{ width: `${policy.rollout_percentage}%` }}
                          />
                        </div>
                        <span className="text-xs text-slate-600">
                          {policy.rollout_percentage}%
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-500">
                      {formatDate(policy.created_at)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Scope hierarchy explainer */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <h3 className="text-sm font-semibold text-slate-800 mb-3">Policy Scope Hierarchy</h3>
        <p className="text-xs text-slate-500 mb-3">
          Policies inherit downward. A transition-level policy overrides workflow, which overrides project, which overrides org.
        </p>
        <div className="flex items-center gap-2 text-xs">
          <ScopeBadge scopeType="org" />
          <span className="text-slate-400">→</span>
          <ScopeBadge scopeType="project" />
          <span className="text-slate-400">→</span>
          <ScopeBadge scopeType="workflow" />
          <span className="text-slate-400">→</span>
          <ScopeBadge scopeType="transition" />
        </div>
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
