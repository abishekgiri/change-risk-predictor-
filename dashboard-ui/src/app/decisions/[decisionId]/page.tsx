import Link from "next/link";

import { CopyButton } from "@/components/CopyButton";
import { DecisionExplainTabs } from "@/components/DecisionExplainTabs";
import { TraceInfo } from "@/components/TraceInfo";
import { backendFetch } from "@/lib/backend";
import { describeDecisionOutcome } from "@/lib/clarity";
import { resolveDashboardScope, scopeToQuery } from "@/lib/dashboard-scope";
import type { DecisionExplainer } from "@/lib/types";

export const dynamic = "force-dynamic";

function safeUrl(url?: string | null): string | null {
  if (!url) return null;

  try {
    const parsed = new URL(url, "http://localhost");
    if (parsed.protocol === "http:" || parsed.protocol === "https:") {
      return url;
    }
    if (url.startsWith("/")) {
      return url;
    }
    return null;
  } catch {
    return null;
  }
}

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
  const decisionSummary = describeDecisionOutcome({
    decision,
    riskScore: explainer.data.risk.score,
    bindingVerified: binding.binding_verified,
  });
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
  const safeReplay = safeUrl(replayUrl);

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
          <h1 className="text-2xl font-semibold text-slate-900">
            {decision.outcome === "BLOCK" ? "Why This Was Blocked" : "Release Decision Summary"}
          </h1>
          <p className="mt-1 text-sm text-slate-600">
            Plain-language explanation for buyers, auditors, and operators reviewing a governed release decision.
          </p>
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
              Policy changes
            </Link>
            <Link href={scopedHref("/overrides")} className="text-indigo-700 hover:underline">
              View exceptions
            </Link>
            {safeReplay ? (
              <a
                href={safeReplay}
                target="_blank"
                rel="noopener noreferrer"
                className="text-indigo-700 hover:underline"
              >
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

      <section className="grid gap-4 md:grid-cols-3">
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Decision</p>
          <p className="mt-2 text-lg font-semibold text-slate-900">
            {decision.outcome === "BLOCK" ? "Blocked before release" : "Allowed to proceed"}
          </p>
          <p className="mt-2 text-sm text-slate-700">{decisionSummary.plainLanguage}</p>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Policy</p>
          <p className="mt-2 text-lg font-semibold text-slate-900">
            {binding.binding_verified ? "Verified release rule applied" : "Release rule evidence attached"}
          </p>
          <p className="mt-2 text-sm text-slate-700">
            {binding.policy_hash
              ? "This decision is tied to a specific policy snapshot, so the exact control can be traced later."
              : "Policy hash details were not attached to this decision."}
          </p>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Evidence</p>
          <p className="mt-2 text-lg font-semibold text-slate-900">
            {explainer.data.signals.length} signal{explainer.data.signals.length === 1 ? "" : "s"} reviewed
          </p>
          <p className="mt-2 text-sm text-slate-700">
            {explainer.data.signals[0]
              ? `Primary signal: ${explainer.data.signals[0].name}.`
              : "No signal details were attached to this decision."}
          </p>
        </div>
      </section>

      <div className="grid gap-4 lg:grid-cols-[1.3fr,1fr]">
        <section
          className={`rounded-xl border p-4 shadow-sm ${
            decision.outcome === "BLOCK"
              ? "border-rose-200 bg-rose-50 text-rose-900"
              : "border-emerald-200 bg-emerald-50 text-emerald-900"
          }`}
        >
          <p className="text-xs font-semibold uppercase tracking-wide">Decision Summary</p>
          <h2 className="mt-2 text-xl font-semibold">{decisionSummary.headline}</h2>
          <p className="mt-2 text-sm">{decisionSummary.plainLanguage}</p>
          <div className="mt-4 grid gap-3 md:grid-cols-2">
            <div className="rounded-lg bg-white/70 p-3">
              <p className="text-xs font-semibold uppercase tracking-wide text-current">Business impact</p>
              <p className="mt-2 text-sm">{decisionSummary.businessImpact}</p>
            </div>
            <div className="rounded-lg bg-white/70 p-3">
              <p className="text-xs font-semibold uppercase tracking-wide text-current">Recommended next step</p>
              <p className="mt-2 text-sm">{decisionSummary.nextStep}</p>
            </div>
          </div>
        </section>

        <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Audit Lens</p>
          <h3 className="mt-2 text-lg font-semibold text-slate-900">Control evidence attached</h3>
          <ul className="mt-3 space-y-2 text-sm text-slate-700">
            <li>{binding.binding_verified ? "Immutable policy snapshot verified." : "Decision hashes are present; snapshot verification should be confirmed."}</li>
            <li>{explainer.data.evidence_links.length} linked evidence artifact{explainer.data.evidence_links.length === 1 ? "" : "s"} available.</li>
            <li>{safeReplay ? "Deterministic replay link is available." : "Replay link is not available for this decision."}</li>
            <li>Risk posture: {decisionSummary.riskLabel}.</li>
          </ul>
          <p className="mt-3 text-xs text-slate-600">{decisionSummary.auditLens}</p>
        </section>
      </div>

      <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm" data-testid="snapshot-binding">
        <h3 className="text-sm font-semibold text-slate-800">Snapshot Binding</h3>
        <p className="mt-2 text-xs text-slate-600">
          These hashes identify the exact policy snapshot and decision evidence used for this outcome.
        </p>
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
              <h3 className="text-sm font-semibold text-slate-800">Why this was blocked</h3>
              <p className="mt-2 text-sm text-rose-700" data-testid="blocked-because">
                {decisionSummary.plainLanguage}
              </p>
              <p className="mt-2 text-xs text-slate-600">Reason code: {decision.reason_code || "No reason code recorded."}</p>
            </>
          ) : (
            <>
              <h3 className="text-sm font-semibold text-slate-800">Why this was allowed</h3>
              <p className="mt-2 text-sm text-emerald-700">{decisionSummary.plainLanguage}</p>
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
              explainer.data.evidence_links.map((link, idx) => {
                const safePath = safeUrl(link.path);
                return (
                  <div key={`${link.id}-${idx}`} className="rounded-md border border-slate-100 p-2">
                    <div className="flex items-center justify-between gap-2">
                      <p className="font-medium text-slate-900">{link.label || link.id || "evidence"}</p>
                      {link.path ? <CopyButton value={link.path} label="Copy path" compact /> : null}
                    </div>
                    <p className="mt-1 text-xs text-slate-600">
                      {link.type} • {link.id}
                    </p>
                    {safePath ? (
                      <a
                        href={safePath}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="mt-1 inline-block text-xs text-indigo-700 hover:underline"
                      >
                        Open
                      </a>
                    ) : null}
                  </div>
                );
              })
            ) : (
              <p className="text-slate-500">No evidence links.</p>
            )}
          </div>
          <div className="mt-4 border-t border-slate-100 pt-3">
            <p className="text-sm font-medium text-slate-800">Replay</p>
            <p className="mt-1 text-xs text-slate-600">Expires: {explainer.data.replay.expires_at || "-"}</p>
            <div className="mt-2 flex flex-wrap gap-2">
              {safeReplay ? (
                <a
                  href={safeReplay}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex rounded-md border border-slate-200 px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50"
                >
                  Open replay
                </a>
              ) : null}
              {safeReplay ? <CopyButton value={safeReplay} label="Copy replay URL" /> : null}
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
