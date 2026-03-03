import { CopyValueButton } from "@/components/CopyValueButton";
import { JsonPanel } from "@/components/JsonPanel";
import { KpiCard } from "@/components/KpiCard";
import { TraceInfo } from "@/components/TraceInfo";
import { backendFetch } from "@/lib/backend";
import { resolveTenantId } from "@/lib/tenant";
import type { DecisionExplainer } from "@/lib/types";

export default async function DecisionPage({
  params,
  searchParams,
}: {
  params: { decisionId: string };
  searchParams: { tenant_id?: string | string[] };
}) {
  const tenantId = resolveTenantId(searchParams.tenant_id);
  const explainer = await backendFetch<DecisionExplainer>(
    `/dashboard/decisions/${encodeURIComponent(params.decisionId)}/explainer`,
    {
      method: "GET",
      query: { tenant_id: tenantId },
    },
  );

  const { decision, snapshot_binding: binding } = explainer.data;

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900">Decision Explorer</h1>
          <p className="mt-1 text-sm text-slate-600">
            {decision.decision_id} • {decision.outcome}
          </p>
          {decision.blocked_because ? (
            <p className="mt-2 text-sm text-rose-700">{decision.blocked_because}</p>
          ) : null}
        </div>
        <TraceInfo traceId={explainer.data.trace_id ?? explainer.traceId} />
      </div>

      <section className="grid gap-4 md:grid-cols-3">
        <KpiCard label="Outcome" value={decision.outcome} helper={decision.reason_code || "No reason code"} />
        <KpiCard label="Risk Score" value={explainer.data.risk.score.toFixed(3)} />
        <KpiCard label="Signals" value={String(explainer.data.signals.length)} />
      </section>

      <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <h3 className="text-sm font-semibold text-slate-800">Snapshot Binding</h3>
        <ul className="mt-3 space-y-2 text-sm">
          <li className="flex items-center justify-between gap-3">
            <span className="font-mono text-xs text-slate-700">policy_hash: {binding.policy_hash || "-"}</span>
            <CopyValueButton value={binding.policy_hash || ""} />
          </li>
          <li className="flex items-center justify-between gap-3">
            <span className="font-mono text-xs text-slate-700">snapshot_hash: {binding.snapshot_hash || "-"}</span>
            <CopyValueButton value={binding.snapshot_hash || ""} />
          </li>
          <li className="flex items-center justify-between gap-3">
            <span className="font-mono text-xs text-slate-700">decision_hash: {binding.decision_hash || "-"}</span>
            <CopyValueButton value={binding.decision_hash || ""} />
          </li>
        </ul>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <h3 className="text-sm font-semibold text-slate-800">Signals</h3>
          <div className="mt-3 overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
                  <th className="py-2 pr-2 text-left">Name</th>
                  <th className="py-2 pr-2 text-left">Value</th>
                  <th className="py-2 pr-2 text-left">Source</th>
                  <th className="py-2 pr-2 text-left">Confidence</th>
                </tr>
              </thead>
              <tbody>
                {explainer.data.signals.map((signal) => (
                  <tr key={signal.name} className="border-b border-slate-100">
                    <td className="py-2 pr-2">{signal.name}</td>
                    <td className="py-2 pr-2 font-mono text-xs">{JSON.stringify(signal.value)}</td>
                    <td className="py-2 pr-2">{signal.source || "-"}</td>
                    <td className="py-2 pr-2">{signal.confidence ?? "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <h3 className="text-sm font-semibold text-slate-800">Risk Components</h3>
          <div className="mt-3 overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
                  <th className="py-2 pr-2 text-left">Name</th>
                  <th className="py-2 pr-2 text-left">Value</th>
                  <th className="py-2 pr-2 text-left">Weight</th>
                  <th className="py-2 pr-2 text-left">Notes</th>
                </tr>
              </thead>
              <tbody>
                {explainer.data.risk.components.map((component, index) => (
                  <tr key={`${component.name}-${index}`} className="border-b border-slate-100">
                    <td className="py-2 pr-2">{component.name}</td>
                    <td className="py-2 pr-2">{String(component.value)}</td>
                    <td className="py-2 pr-2">{component.weight ?? "-"}</td>
                    <td className="py-2 pr-2">{component.notes || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="mt-3 text-sm font-semibold text-slate-900">Total score: {explainer.data.risk.score.toFixed(3)}</p>
        </div>
      </div>

      <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <h3 className="text-sm font-semibold text-slate-800">Replay</h3>
        <p className="mt-2 text-sm text-slate-600">Use replay to verify deterministic decision behavior.</p>
        <a
          href={`${explainer.data.replay.path}?token=${encodeURIComponent(explainer.data.replay.token)}`}
          className="mt-3 inline-flex rounded-md border border-slate-200 px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50"
        >
          Replay Decision
        </a>
      </div>

      <JsonPanel title="Evaluation Tree" value={explainer.data.evaluation_tree} />
      <JsonPanel title="Evidence Links" value={explainer.data.evidence_links} />
    </div>
  );
}
