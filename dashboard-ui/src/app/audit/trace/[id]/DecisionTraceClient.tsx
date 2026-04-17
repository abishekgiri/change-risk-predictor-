"use client";

import Link from "next/link";
import { useParams, useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";
import { callDashboardApi } from "@/lib/api";

interface Hashes {
  input_hash: string | null;
  policy_hash: string | null;
  decision_hash: string | null;
  replay_hash: string | null;
}

interface DecisionNode {
  rg_decision_id: string;
  decision_id: string;
  tenant_id: string;
  repo: string | null;
  status: string;
  reason_code: string | null;
  message: string | null;
  actor: string | null;
  created_at: string;
  hashes: Hashes;
  inputs_present: Record<string, boolean>;
  input_snapshot: Record<string, unknown>;
  policy_bindings: Array<{ policy_id: string; policy_version: string; policy_hash: string }>;
}

interface CheckpointNode {
  checkpoint_id: string | null;
  root_hash: string | null;
  cadence: string | null;
  period_end: string;
  event_count: number | null;
  signature_algorithm: string | null;
  signature_value: string;
  created_at: string;
  covers_decision: boolean;
}

interface AnchorNode {
  job_id: string | null;
  root_hash: string | null;
  status: string | null;
  external_anchor_id: string | null;
  date_utc: string | null;
  submitted_at: string;
  confirmed_at: string;
}

interface Completeness {
  decision_recorded: boolean;
  hashes_complete: boolean;
  checkpointed: boolean;
  externally_anchored: boolean;
  standalone_auditable: boolean;
}

interface TraceResult {
  ok: boolean;
  rg_decision_id: string;
  decision: DecisionNode;
  checkpoint: CheckpointNode | null;
  anchor: AnchorNode | null;
  completeness: Completeness;
  verification_command: string;
}

interface VerifyResult {
  ok: boolean;
  verified: boolean;
  stored_replay_hash?: string;
  computed_replay_hash?: string;
  tamper_evidence?: string;
  error?: string;
}

const STATUS_STYLES: Record<string, string> = {
  ALLOWED: "bg-emerald-50 text-emerald-700 border-emerald-200",
  BLOCKED: "bg-rose-50 text-rose-700 border-rose-200",
  CONDITIONAL: "bg-amber-50 text-amber-700 border-amber-200",
};

function NodeCard({ title, icon, complete, children }: {
  title: string; icon: string; complete: boolean; children: React.ReactNode;
}) {
  return (
    <div className={`rounded-xl border p-5 ${complete ? "border-emerald-200 bg-white" : "border-slate-200 bg-slate-50"}`}>
      <div className="flex items-center gap-2 mb-3">
        <span className="text-base">{icon}</span>
        <h3 className="text-sm font-semibold text-slate-800">{title}</h3>
        <span className={`ml-auto inline-flex h-5 w-5 items-center justify-center rounded-full text-[10px] font-bold ${complete ? "bg-emerald-100 text-emerald-700" : "bg-slate-200 text-slate-400"}`}>
          {complete ? "✓" : "–"}
        </span>
      </div>
      {children}
    </div>
  );
}

function HashRow({ label, value }: { label: string; value: string | null | undefined }) {
  if (!value) return null;
  return (
    <div className="flex items-center gap-2">
      <span className="w-16 shrink-0 text-[10px] font-medium text-slate-500">{label}</span>
      <span className="font-mono text-[10px] text-slate-700 truncate">{value}</span>
    </div>
  );
}

export function DecisionTraceClient() {
  const params = useParams<{ id: string }>();
  const searchParams = useSearchParams();
  const tenantId = searchParams.get("tenant_id") || "default";
  const decisionId = params.id;

  const [trace, setTrace] = useState<TraceResult | null>(null);
  const [verify, setVerify] = useState<VerifyResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!decisionId) return;
    setLoading(true);
    Promise.all([
      callDashboardApi<TraceResult>(
        `/api/dashboard/audit/trace/${encodeURIComponent(decisionId)}?tenant_id=${encodeURIComponent(tenantId)}`
      ),
      callDashboardApi<VerifyResult>(
        `/api/dashboard/decisions/${encodeURIComponent(decisionId)}/verify?tenant_id=${encodeURIComponent(tenantId)}`
      ),
    ])
      .then(([t, v]) => { setTrace(t); setVerify(v); })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load trace"))
      .finally(() => setLoading(false));
  }, [decisionId, tenantId]);

  if (loading) return <div className="text-sm text-slate-500">Loading trace…</div>;
  if (error) return (
    <div className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">{error}</div>
  );
  if (!trace) return null;

  const { decision, checkpoint, anchor, completeness } = trace;
  const statusStyle = STATUS_STYLES[decision.status] ?? "bg-slate-100 text-slate-600 border-slate-200";

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <Link href={`/decisions?tenant_id=${encodeURIComponent(tenantId)}`}
          className="text-sm text-indigo-600 hover:text-indigo-800">
          ← Decision Registry
        </Link>
        <div className="mt-2 flex items-start gap-4 flex-wrap">
          <div>
            <h1 className="text-xl font-bold text-slate-900 font-mono">{trace.rg_decision_id}</h1>
            <p className="text-xs text-slate-400 font-mono mt-0.5">{decision.decision_id}</p>
          </div>
          <span className={`mt-1 inline-flex rounded-full border px-3 py-1 text-sm font-semibold ${statusStyle}`}>
            {decision.status}
          </span>
          {verify && (
            <span className={`mt-1 inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-semibold ${verify.verified ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-rose-200 bg-rose-50 text-rose-700"}`}>
              <span className={`h-1.5 w-1.5 rounded-full ${verify.verified ? "bg-emerald-500" : "bg-rose-500"}`} />
              {verify.verified ? "Integrity verified" : "INTEGRITY MISMATCH"}
            </span>
          )}
        </div>
      </div>

      {/* Completeness bar */}
      <div className="flex flex-wrap gap-3">
        {[
          { label: "Recorded", ok: completeness.decision_recorded },
          { label: "Hashes", ok: completeness.hashes_complete },
          { label: "Checkpointed", ok: completeness.checkpointed },
          { label: "Anchored", ok: completeness.externally_anchored },
          { label: "Standalone-auditable", ok: completeness.standalone_auditable },
        ].map(({ label, ok }) => (
          <span key={label} className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium ${ok ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-slate-200 bg-slate-50 text-slate-400"}`}>
            <span className={`h-1.5 w-1.5 rounded-full ${ok ? "bg-emerald-500" : "bg-slate-300"}`} />
            {label}
          </span>
        ))}
      </div>

      {/* Audit graph — 3 nodes */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">

        {/* Node 1: Decision */}
        <NodeCard title="Decision" icon="⚖️" complete={completeness.decision_recorded}>
          <div className="space-y-1.5 text-xs">
            <p><span className="font-medium text-slate-500">Repo:</span> <span className="font-mono">{decision.repo || "—"}</span></p>
            <p><span className="font-medium text-slate-500">Actor:</span> {decision.actor || "—"}</p>
            <p><span className="font-medium text-slate-500">Reason:</span> {decision.reason_code || "—"}</p>
            <p className="text-slate-600 italic">{decision.message}</p>
            <div className="mt-2 pt-2 border-t border-slate-100 space-y-0.5">
              <HashRow label="input" value={decision.hashes.input_hash} />
              <HashRow label="policy" value={decision.hashes.policy_hash} />
              <HashRow label="decision" value={decision.hashes.decision_hash} />
              <HashRow label="replay" value={decision.hashes.replay_hash} />
            </div>
            {decision.policy_bindings.length > 0 && (
              <div className="mt-2 pt-2 border-t border-slate-100">
                <p className="font-medium text-slate-500 mb-1">Policies applied</p>
                {decision.policy_bindings.map((b, i) => (
                  <p key={i} className="font-mono text-[10px] text-slate-500">
                    {b.policy_id}@{b.policy_version}
                  </p>
                ))}
              </div>
            )}
            <p className="text-[10px] text-slate-400 pt-1">
              {new Date(decision.created_at).toLocaleString()}
            </p>
          </div>
        </NodeCard>

        {/* Node 2: Checkpoint */}
        <NodeCard title="Signed Checkpoint" icon="🔐" complete={completeness.checkpointed}>
          {checkpoint ? (
            <div className="space-y-1.5 text-xs">
              <p><span className="font-medium text-slate-500">Cadence:</span> {checkpoint.cadence}</p>
              <p><span className="font-medium text-slate-500">Period:</span> {checkpoint.period_end}</p>
              <p><span className="font-medium text-slate-500">Events:</span> {checkpoint.event_count}</p>
              <p><span className="font-medium text-slate-500">Algorithm:</span> {checkpoint.signature_algorithm}</p>
              <div className="mt-2 pt-2 border-t border-slate-100 space-y-0.5">
                <HashRow label="root" value={checkpoint.root_hash} />
                <p className="font-mono text-[10px] text-slate-400">sig: {checkpoint.signature_value}</p>
              </div>
              <p className="text-[10px] text-slate-400 pt-1">
                Created: {new Date(checkpoint.created_at).toLocaleString()}
              </p>
            </div>
          ) : (
            <p className="text-xs text-slate-400 italic">
              No checkpoint yet — scheduled runs every 24h. Decisions are sealed at the next checkpoint.
            </p>
          )}
        </NodeCard>

        {/* Node 3: External Anchor */}
        <NodeCard title="External Anchor (RFC 3161)" icon="⚓" complete={completeness.externally_anchored}>
          {anchor ? (
            <div className="space-y-1.5 text-xs">
              <p>
                <span className="font-medium text-slate-500">Status:</span>{" "}
                <span className={anchor.status === "CONFIRMED" ? "text-emerald-600 font-semibold" : "text-amber-600"}>
                  {anchor.status}
                </span>
              </p>
              {anchor.external_anchor_id && (
                <p><span className="font-medium text-slate-500">Anchor ID:</span> <span className="font-mono text-[10px]">{anchor.external_anchor_id}</span></p>
              )}
              <p><span className="font-medium text-slate-500">Date:</span> {anchor.date_utc}</p>
              <div className="mt-2 pt-2 border-t border-slate-100">
                <HashRow label="root" value={anchor.root_hash} />
              </div>
              {anchor.confirmed_at && (
                <p className="text-[10px] text-slate-400 pt-1">
                  Confirmed: {new Date(anchor.confirmed_at).toLocaleString()}
                </p>
              )}
            </div>
          ) : (
            <p className="text-xs text-slate-400 italic">
              Pending external anchor — set <code className="text-[10px]">RELEASEGATE_RFC3161_TSA_URL</code> to enable timestamp authority anchoring.
            </p>
          )}
        </NodeCard>
      </div>

      {/* Input snapshot */}
      {Object.keys(decision.input_snapshot).length > 0 && (
        <div className="rounded-xl border border-slate-200 bg-white shadow-sm">
          <div className="border-b border-slate-100 px-4 py-3">
            <h3 className="text-sm font-semibold text-slate-800">Input Snapshot</h3>
            <p className="text-xs text-slate-500">Signals and context captured at evaluation time</p>
          </div>
          <div className="p-4">
            <pre className="overflow-x-auto text-[11px] text-slate-700 font-mono leading-relaxed">
              {JSON.stringify(decision.input_snapshot, null, 2)}
            </pre>
          </div>
        </div>
      )}

      {/* Offline verification */}
      <div className="rounded-xl border border-slate-200 bg-slate-50 p-5 space-y-2">
        <h3 className="text-sm font-semibold text-slate-800">Offline Verification</h3>
        <p className="text-xs text-slate-500">Verify this decision without access to ReleaseGate.</p>
        <pre className="mt-2 overflow-x-auto rounded-lg bg-slate-900 p-4 text-xs text-slate-200 font-mono leading-relaxed">
          {trace.verification_command}
        </pre>
      </div>
    </div>
  );
}
