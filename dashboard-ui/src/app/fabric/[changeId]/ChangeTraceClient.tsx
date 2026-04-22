"use client";

import Link from "next/link";
import { useParams, useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";
import { callDashboardApi } from "@/lib/api";

interface ChangeRecord {
  change_id: string;
  lifecycle_state: string;
  enforcement_mode: string;
  jira_issue_key: string | null;
  pr_repo: string | null;
  pr_number: number | null;
  pr_sha: string | null;
  deploy_id: string | null;
  rg_decision_ids: string[];
  incident_id: string | null;
  hotfix_id: string | null;
  environment: string | null;
  actor: string | null;
  missing_links: string[];
  violation_codes: string[];
  linked_at: string | null;
  approved_at: string | null;
  deployed_at: string | null;
  incident_at: string | null;
  closed_at: string | null;
  created_at: string;
  updated_at: string;
}

interface DecisionNode {
  rg_decision_id: string;
  decision_id: string | null;
  status: string | null;
  repo: string | null;
  created_at: string | null;
  replay_hash: string | null;
}

interface DeployNode {
  deploy_id: string;
  environment: string | null;
  deployed_at: string | null;
  contract_verdict: string | null;
  violation_codes: string[];
}

interface CorrelationNode {
  correlation_id: string;
  jira_issue_key: string | null;
  pr_repo: string | null;
  deploy_id: string | null;
  incident_id: string | null;
  environment: string | null;
}

interface Completeness {
  has_jira: boolean;
  has_pr: boolean;
  has_decision: boolean;
  has_deploy: boolean;
  has_incident_traced: boolean;
  lifecycle_closed: boolean;
}

interface TraceResult {
  ok: boolean;
  change_id: string;
  record: ChangeRecord;
  decisions: DecisionNode[];
  deployment: DeployNode | null;
  correlation: CorrelationNode | null;
  completeness: Completeness;
}

const STATE_STYLES: Record<string, string> = {
  CREATED:            "bg-slate-100 text-slate-600 border-slate-200",
  LINKED:             "bg-blue-50 text-blue-700 border-blue-200",
  APPROVED:           "bg-indigo-50 text-indigo-700 border-indigo-200",
  DEPLOYED:           "bg-emerald-50 text-emerald-700 border-emerald-200",
  INCIDENT_ACTIVE:    "bg-rose-50 text-rose-700 border-rose-200",
  HOTFIX_IN_PROGRESS: "bg-amber-50 text-amber-700 border-amber-200",
  VERIFIED:           "bg-teal-50 text-teal-700 border-teal-200",
  CLOSED:             "bg-slate-100 text-slate-500 border-slate-200",
  BLOCKED:            "bg-rose-100 text-rose-800 border-rose-300",
};

const LIFECYCLE_STEPS = [
  { state: "CREATED",            label: "Created",   field: "created_at" as keyof ChangeRecord },
  { state: "LINKED",             label: "Linked",    field: "linked_at" as keyof ChangeRecord },
  { state: "APPROVED",           label: "Approved",  field: "approved_at" as keyof ChangeRecord },
  { state: "DEPLOYED",           label: "Deployed",  field: "deployed_at" as keyof ChangeRecord },
  { state: "INCIDENT_ACTIVE",    label: "Incident",  field: "incident_at" as keyof ChangeRecord },
  { state: "VERIFIED",           label: "Verified",  field: null },
  { state: "CLOSED",             label: "Closed",    field: "closed_at" as keyof ChangeRecord },
];

function NodeCard({ title, icon, complete, children }: {
  title: string; icon: string; complete: boolean; children: React.ReactNode;
}) {
  return (
    <div className={`rounded-xl border p-5 ${complete ? "border-emerald-200 bg-white" : "border-slate-200 bg-slate-50"}`}>
      <div className="flex items-center gap-2 mb-3">
        <span className="text-base">{icon}</span>
        <h3 className="text-sm font-semibold text-slate-800">{title}</h3>
        <span className={`ml-auto inline-flex h-5 w-5 items-center justify-center rounded-full text-[10px] font-bold
          ${complete ? "bg-emerald-100 text-emerald-700" : "bg-slate-200 text-slate-400"}`}>
          {complete ? "✓" : "–"}
        </span>
      </div>
      {children}
    </div>
  );
}

export function ChangeTraceClient() {
  const params = useParams<{ changeId: string }>();
  const searchParams = useSearchParams();
  const tenantId = searchParams.get("tenant_id") || "";
  const changeId = params.changeId;

  const [trace, setTrace] = useState<TraceResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!changeId) return;
    setLoading(true);
    callDashboardApi<TraceResult>(
      `/api/dashboard/fabric/changes/${encodeURIComponent(changeId)}/trace?tenant_id=${encodeURIComponent(tenantId)}`
    )
      .then(setTrace)
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load trace"))
      .finally(() => setLoading(false));
  }, [changeId, tenantId]);

  if (loading) return <div className="text-sm text-slate-500">Loading change trace…</div>;
  if (error) return <div className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">{error}</div>;
  if (!trace) return null;

  const { record, completeness } = trace;
  const stateStyle = STATE_STYLES[record.lifecycle_state] ?? "bg-slate-100 text-slate-600 border-slate-200";

  // Determine which lifecycle steps are reached
  const stateOrder = LIFECYCLE_STEPS.map(s => s.state);
  const currentIdx = stateOrder.indexOf(record.lifecycle_state);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <Link href={`/fabric?tenant_id=${encodeURIComponent(tenantId)}`}
          className="text-sm text-indigo-600 hover:text-indigo-800">
          ← Governance Fabric
        </Link>
        <div className="mt-2 flex items-start gap-4 flex-wrap">
          <div>
            <h1 className="text-xl font-bold text-slate-900 font-mono">{trace.change_id}</h1>
            <p className="text-xs text-slate-400 mt-0.5">
              {record.environment} · {record.actor || "ci"} · created {new Date(record.created_at).toLocaleString()}
            </p>
          </div>
          <span className={`mt-1 inline-flex rounded-full border px-3 py-1 text-sm font-semibold ${stateStyle}`}>
            {record.lifecycle_state}
          </span>
          <span className={`mt-1 inline-flex rounded-full border px-3 py-1 text-xs font-medium
            ${record.enforcement_mode === "STRICT" ? "border-slate-300 bg-slate-100 text-slate-600" : "border-amber-200 bg-amber-50 text-amber-700"}`}>
            {record.enforcement_mode}
          </span>
        </div>
      </div>

      {/* Violations */}
      {record.violation_codes.length > 0 && (
        <div className="rounded-xl border border-rose-200 bg-rose-50 p-4">
          <p className="text-sm font-semibold text-rose-800 mb-2">Missing link violations</p>
          <ul className="space-y-1">
            {record.violation_codes.map((code) => (
              <li key={code} className="text-xs text-rose-700 font-mono">✗ {code}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Lifecycle timeline */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <h3 className="text-sm font-semibold text-slate-800 mb-4">Lifecycle</h3>
        <div className="flex items-center gap-0">
          {LIFECYCLE_STEPS.filter(s => !["INCIDENT_ACTIVE"].includes(s.state)).map((step, i, arr) => {
            const reached = stateOrder.indexOf(step.state) <= currentIdx;
            const isCurrent = step.state === record.lifecycle_state;
            return (
              <div key={step.state} className="flex items-center">
                <div className={`flex flex-col items-center ${i > 0 ? "" : ""}`}>
                  <div className={`h-7 w-7 rounded-full flex items-center justify-center text-xs font-bold border-2
                    ${isCurrent ? "border-indigo-500 bg-indigo-500 text-white" :
                      reached ? "border-emerald-500 bg-emerald-500 text-white" :
                      "border-slate-200 bg-white text-slate-400"}`}>
                    {reached && !isCurrent ? "✓" : i + 1}
                  </div>
                  <span className={`mt-1 text-[10px] font-medium whitespace-nowrap
                    ${isCurrent ? "text-indigo-600" : reached ? "text-emerald-600" : "text-slate-400"}`}>
                    {step.label}
                  </span>
                </div>
                {i < arr.length - 1 && (
                  <div className={`h-0.5 w-8 mb-4 ${reached && stateOrder.indexOf(arr[i + 1].state) <= currentIdx ? "bg-emerald-400" : "bg-slate-200"}`} />
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Completeness badges */}
      <div className="flex flex-wrap gap-2">
        {[
          { label: "Jira",     ok: completeness.has_jira },
          { label: "PR",       ok: completeness.has_pr },
          { label: "Decision", ok: completeness.has_decision },
          { label: "Deploy",   ok: completeness.has_deploy },
          { label: "Incident traced", ok: completeness.has_incident_traced || !record.incident_id },
          { label: "Closed",   ok: completeness.lifecycle_closed },
        ].map(({ label, ok }) => (
          <span key={label} className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium
            ${ok ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-slate-200 bg-slate-50 text-slate-400"}`}>
            <span className={`h-1.5 w-1.5 rounded-full ${ok ? "bg-emerald-500" : "bg-slate-300"}`} />
            {label}
          </span>
        ))}
      </div>

      {/* 5-node audit graph */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">

        {/* Node 1: Change */}
        <NodeCard title="Change" icon="🔄" complete={completeness.has_jira && completeness.has_pr}>
          <div className="space-y-1.5 text-xs">
            <p><span className="font-medium text-slate-500">Jira:</span> <span className="font-mono">{record.jira_issue_key || "—"}</span></p>
            <p><span className="font-medium text-slate-500">PR:</span> <span className="font-mono">{record.pr_repo ? `${record.pr_repo}${record.pr_number ? ` #${record.pr_number}` : ""}` : "—"}</span></p>
            {record.pr_sha && <p><span className="font-medium text-slate-500">SHA:</span> <span className="font-mono text-[10px]">{record.pr_sha.slice(0, 12)}</span></p>}
            <p><span className="font-medium text-slate-500">Actor:</span> {record.actor || "—"}</p>
          </div>
        </NodeCard>

        {/* Node 2: Decision(s) */}
        <NodeCard title="Governance Decisions" icon="⚖️" complete={completeness.has_decision}>
          {trace.decisions.length > 0 ? (
            <div className="space-y-2">
              {trace.decisions.map((d) => (
                <div key={d.rg_decision_id} className="text-xs border-t border-slate-100 pt-2 first:border-0 first:pt-0">
                  <Link href={`/audit/trace/${encodeURIComponent(d.rg_decision_id)}?tenant_id=${encodeURIComponent(tenantId)}`}
                    className="font-mono text-indigo-600 hover:text-indigo-800 text-[10px]">
                    {d.rg_decision_id}
                  </Link>
                  <p><span className="font-medium text-slate-500">Status:</span>{" "}
                    <span className={d.status === "ALLOWED" ? "text-emerald-600 font-semibold" : "text-rose-600 font-semibold"}>
                      {d.status || "—"}
                    </span>
                  </p>
                  {d.created_at && <p className="text-[10px] text-slate-400">{new Date(d.created_at).toLocaleString()}</p>}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-slate-400 italic">No decisions linked yet. Run <code className="text-[10px]">POST /decisions/declare</code> before deploying.</p>
          )}
        </NodeCard>

        {/* Node 3: Deployment */}
        <NodeCard title="Deployment" icon="🚀" complete={completeness.has_deploy}>
          {trace.deployment ? (
            <div className="space-y-1.5 text-xs">
              <p><span className="font-medium text-slate-500">Deploy ID:</span> <span className="font-mono text-[10px]">{trace.deployment.deploy_id}</span></p>
              <p><span className="font-medium text-slate-500">Environment:</span> {trace.deployment.environment}</p>
              <p><span className="font-medium text-slate-500">Verdict:</span>{" "}
                <span className={trace.deployment.contract_verdict === "ALLOW" ? "text-emerald-600 font-semibold" : "text-rose-600 font-semibold"}>
                  {trace.deployment.contract_verdict || "—"}
                </span>
              </p>
              {trace.deployment.violation_codes.length > 0 && (
                <p className="text-rose-600 text-[10px]">{trace.deployment.violation_codes.join(", ")}</p>
              )}
              {trace.deployment.deployed_at && (
                <p className="text-[10px] text-slate-400">{new Date(trace.deployment.deployed_at).toLocaleString()}</p>
              )}
            </div>
          ) : (
            <p className="text-xs text-slate-400 italic">No deployment recorded yet.</p>
          )}
        </NodeCard>

        {/* Node 4: Incident */}
        <NodeCard title="Incident" icon="🚨" complete={!record.incident_id || completeness.has_incident_traced}>
          {record.incident_id ? (
            <div className="space-y-1.5 text-xs">
              <p><span className="font-medium text-slate-500">Incident ID:</span> <span className="font-mono">{record.incident_id}</span></p>
              {record.hotfix_id && <p><span className="font-medium text-slate-500">Hotfix:</span> <span className="font-mono">{record.hotfix_id}</span></p>}
              {record.incident_at && <p className="text-[10px] text-slate-400">Opened: {new Date(record.incident_at).toLocaleString()}</p>}
            </div>
          ) : (
            <p className="text-xs text-slate-400 italic">No incident linked — change was clean.</p>
          )}
        </NodeCard>

        {/* Node 5: Cross-system correlation */}
        <NodeCard title="Correlation Record" icon="🔗" complete={!!trace.correlation}>
          {trace.correlation ? (
            <div className="space-y-1.5 text-xs">
              <p><span className="font-medium text-slate-500">Correlation ID:</span></p>
              <p className="font-mono text-[10px] text-slate-600 truncate">{trace.correlation.correlation_id}</p>
              <div className="mt-1 pt-1 border-t border-slate-100 space-y-0.5">
                {[
                  { label: "Jira",   val: trace.correlation.jira_issue_key },
                  { label: "Repo",   val: trace.correlation.pr_repo },
                  { label: "Deploy", val: trace.correlation.deploy_id },
                ].map(({ label, val }) => val && (
                  <p key={label} className="text-[10px] text-slate-500">
                    <span className="font-medium">{label}:</span> <span className="font-mono">{val}</span>
                  </p>
                ))}
              </div>
            </div>
          ) : (
            <p className="text-xs text-slate-400 italic">No cross-system correlation found.</p>
          )}
        </NodeCard>
      </div>

      <p className="text-xs text-slate-400">
        Last updated {new Date(record.updated_at).toLocaleString()}
      </p>
    </div>
  );
}
