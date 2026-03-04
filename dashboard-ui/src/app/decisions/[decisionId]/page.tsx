import Link from "next/link";

import { CopyButton } from "@/components/CopyButton";
import { DecisionExplainTabs } from "@/components/DecisionExplainTabs";
import { TraceInfo } from "@/components/TraceInfo";
import { backendFetch } from "@/lib/backend";
import { resolveDashboardScope, scopeToQuery } from "@/lib/dashboard-scope";
import type { DecisionExplainer } from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function DecisionPage({
  params,
  searchParams,
}: {
  params: Promise<{ decisionId: string }>;
  searchParams: Promise<{
    tenant_id?: string | string[];
    from?: string | string[];
    to?: string | string[];
    window_days?: string | string[];
  }>;
}) {
  const resolvedParams = await params;
  const resolvedSearchParams = await searchParams;
  const scope = resolveDashboardScope(resolvedSearchParams);
  const explainer = await backendFetch<DecisionExplainer>(
    `/dashboard/decisions/${encodeURIComponent(resolvedParams.decisionId)}/explainer`,
    {
      method: "GET",
      query: scopeToQuery(scope),
    },
  );

  const { decision, snapshot_binding: binding } = explainer.data;
  const traceId = String(explainer.data.trace_id ?? explainer.traceId ?? "");
  const outcomeBadgeClass =
    decision.outcome === "BLOCK"
      ? "border-rose-200 bg-rose-100 text-rose-700"
      : "border-emerald-200 bg-emerald-100 text-emerald-700";

  const scopedParams = new URLSearchParams();
  scopedParams.set("tenant_id", scope.tenantId);
  if (scope.fromTs) scopedParams.set("from", scope.fromTs);
  if (scope.toTs) scopedParams.set("to", scope.toTs);
  const scopedQuery = scopedParams.toString();
  const scopedHref = (path: string): string => (scopedQuery ? `${path}?${scopedQuery}` : path);

  const replayPath = String(explainer.data.replay.path || "").trim();
  const replayToken = String(explainer.data.replay.token || "").trim();
  const replayUrl = replayPath
    ? replayToken
      ? `${replayPath}${replayPath.includes("?") ? "&" : "?"}token=${encodeURIComponent(replayToken)}`
      : replayPath
    : "";

  const copyBundle = [
    `decision_id=${decision.decision_id || ""}`,
    `trace_id=${traceId}`,
    `policy_hash=${binding.policy_hash || ""}`,
    `snapshot_hash=${binding.snapshot_hash || ""}`,
    `decision_hash=${binding.decision_hash || ""}`,
    `tenant_id=${scope.tenantId}`,
  ].join("\n");

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900">Decision Explorer</h1>
          <div className="mt-2 flex flex-wrap items-center gap-2 text-sm text-slate-600">
            <span className={`inline-flex rounded-md border px-2 py-0.5 text-xs font-semibold ${outcomeBadgeClass}`}>
              {decision.outcome}
            </span>
            <span data-testid="decision-outcome">{decision.decision_id}</span>
            <span>•</span>
            <span>{decision.created_at || "created_at unknown"}</span>
            {decision.reason_code ? (
              <>
                <span>•</span>
                <span>{decision.reason_code}</span>
              </>
            ) : null}
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-3 text-sm">
            <Link href={scopedHref("/policies/diff")} className="text-indigo-700 hover:underline">
              Policy diff
            </Link>
            <Link href={scopedHref("/overrides")} className="text-indigo-700 hover:underline">
              View overrides
            </Link>
            {replayUrl ? (
              <a href={replayUrl} className="text-indigo-700 hover:underline">
                Replay decision
              </a>
            ) : null}
          </div>
        </div>
        <div className="flex flex-col items-end gap-2">
          <TraceInfo traceId={traceId} />
          <div className="flex flex-wrap justify-end gap-2">
            <CopyButton value={decision.decision_id || ""} label="Decision ID" title="Copy decision_id" compact />
            <CopyButton value={binding.policy_hash || ""} label="Policy hash" title="Copy policy_hash" compact />
            <CopyButton value={binding.decision_hash || ""} label="Decision hash" title="Copy decision_hash" compact />
            <CopyButton value={traceId} label="Trace ID" title="Copy trace_id" compact />
            <CopyButton value={copyBundle} label="Copy all IDs" title="Copy all identifiers" />
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm" data-testid="snapshot-binding">
        <h3 className="text-sm font-semibold text-slate-800">Snapshot Binding</h3>
        <ul className="mt-3 space-y-2 text-sm">
          <li className="flex items-center justify-between gap-3">
            <span className="font-mono text-xs text-slate-700">policy_hash: {binding.policy_hash || "-"}</span>
            <CopyButton value={binding.policy_hash || ""} compact />
          </li>
          <li className="flex items-center justify-between gap-3">
            <span className="font-mono text-xs text-slate-700">snapshot_hash: {binding.snapshot_hash || "-"}</span>
            <CopyButton value={binding.snapshot_hash || ""} compact />
          </li>
          <li className="flex items-center justify-between gap-3">
            <span className="font-mono text-xs text-slate-700">decision_hash: {binding.decision_hash || "-"}</span>
            <CopyButton value={binding.decision_hash || ""} compact />
          </li>
        </ul>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          {decision.outcome === "BLOCK" ? (
            <>
              <h3 className="text-sm font-semibold text-slate-800">Why blocked</h3>
              <p className="mt-2 text-sm text-rose-700" data-testid="blocked-because">
                Blocked because: {decision.blocked_because || "No blocked reason provided."}
              </p>
            </>
          ) : (
            <>
              <h3 className="text-sm font-semibold text-slate-800">Why allowed</h3>
              <p className="mt-2 text-sm text-emerald-700">
                Policy conditions satisfied. {decision.reason_code ? `(${decision.reason_code})` : ""}
              </p>
            </>
          )}
          <div className="mt-3 grid gap-2 text-sm text-slate-700 md:grid-cols-2">
            <p>
              <span className="font-medium">Actor:</span> {decision.actor || "-"}
            </p>
            <p>
              <span className="font-medium">Environment:</span> {decision.environment || "-"}
            </p>
            <p>
              <span className="font-medium">Issue:</span> {decision.jira_issue_id || "-"}
            </p>
            <p>
              <span className="font-medium">Workflow:</span> {decision.workflow_id || "-"}
            </p>
            <p>
              <span className="font-medium">Transition:</span> {decision.transition_id || "-"}
            </p>
            <p>
              <span className="font-medium">Reason code:</span> {decision.reason_code || "-"}
            </p>
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <h3 className="text-sm font-semibold text-slate-800">Evidence & Replay</h3>
          <div className="mt-3 space-y-2 text-sm">
            {explainer.data.evidence_links.length ? (
              explainer.data.evidence_links.map((link, idx) => (
                <div key={`${link.id}-${idx}`} className="rounded-md border border-slate-100 p-2">
                  <div className="flex items-center justify-between gap-2">
                    <p className="font-medium text-slate-900">{link.label || link.id || "evidence"}</p>
                    {link.path ? <CopyButton value={link.path} label="Copy path" compact /> : null}
                  </div>
                  <p className="mt-1 text-xs text-slate-600">
                    {link.type} • {link.id}
                  </p>
                  {link.path ? (
                    <a href={link.path} className="mt-1 inline-block text-xs text-indigo-700 hover:underline">
                      Open
                    </a>
                  ) : null}
                </div>
              ))
            ) : (
              <p className="text-slate-500">No evidence links.</p>
            )}
          </div>
          <div className="mt-4 border-t border-slate-100 pt-3">
            <p className="text-sm font-medium text-slate-800">Replay</p>
            <p className="mt-1 text-xs text-slate-600">Expires: {explainer.data.replay.expires_at || "-"}</p>
            <div className="mt-2 flex flex-wrap gap-2">
              {replayUrl ? (
                <a
                  href={replayUrl}
                  className="inline-flex rounded-md border border-slate-200 px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50"
                >
                  Open replay
                </a>
              ) : null}
              {replayUrl ? <CopyButton value={replayUrl} label="Copy replay URL" /> : null}
            </div>
          </div>
        </div>
      </div>

      <DecisionExplainTabs
        risk={explainer.data.risk}
        signals={explainer.data.signals}
        evaluationTree={explainer.data.evaluation_tree}
      />
    </div>
  );
}
