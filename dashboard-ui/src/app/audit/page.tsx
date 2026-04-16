import Link from "next/link";
import { backendFetch } from "@/lib/backend";
import { resolveDashboardScope, scopeToQuery } from "@/lib/dashboard-scope";
import { TraceInfo } from "@/components/TraceInfo";

export const dynamic = "force-dynamic";

interface TrustComponent {
  passes: boolean;
  weight: number;
}

interface TrustStatus {
  tenant_id: string;
  generated_at: string;
  trust_score: number;
  trust_score_max: number;
  trust_components: Record<string, TrustComponent>;
  decisions: { total: number; latest_at: string | null };
  ledger: { valid: boolean; checked: number; broken_chains: number };
  checkpoint: {
    checkpoint_id: string;
    period_id: string;
    root_hash: string;
    signed: boolean;
    event_count: number;
    created_at: string;
    fresh: boolean;
  } | null;
  external_anchors: { count: number; latest_at: string | null };
  signal_freshness: Record<string, unknown>;
  attestations: { total: number; compromised: number };
  immutable_tables: string[];
  tamper_evidence: { append_only_tables: number; trigger_protection: string };
}

const COMPONENT_LABELS: Record<string, { label: string; description: string }> = {
  ledger_integrity: {
    label: "Ledger Integrity",
    description: "All hash chains valid with no broken links",
  },
  checkpoint_fresh: {
    label: "Checkpoint Fresh",
    description: "Latest signed checkpoint is within 36 hours",
  },
  checkpoint_signed: {
    label: "Checkpoint Signed",
    description: "Latest checkpoint has a cryptographic signature",
  },
  signal_freshness_enabled: {
    label: "Signal Freshness",
    description: "Stale signals are rejected (zero-trust mode)",
  },
  no_compromised_keys: {
    label: "Key Integrity",
    description: "No signing keys have been flagged as compromised",
  },
  external_anchors_exist: {
    label: "External Anchoring",
    description: "At least one checkpoint anchored to external system",
  },
};

function scoreColor(score: number): string {
  if (score >= 80) return "text-emerald-600";
  if (score >= 50) return "text-amber-600";
  return "text-rose-600";
}

function scoreBg(score: number): string {
  if (score >= 80) return "bg-emerald-500";
  if (score >= 50) return "bg-amber-500";
  return "bg-rose-500";
}

function formatDate(iso: string | null): string {
  if (!iso) return "Never";
  return new Date(iso).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default async function AuditTrustPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;
  const scope = resolveDashboardScope(params);
  const query = scopeToQuery(scope);

  let trust: TrustStatus | null = null;
  let fetchError: string | null = null;
  let traceId: string | null = null;

  try {
    const { data, traceId: tid } = await backendFetch<TrustStatus>("/audit/trust-status", {
      method: "GET",
      query: { tenant_id: scope.tenantId },
    });
    trust = data;
    traceId = tid;
  } catch (err) {
    fetchError = err instanceof Error ? err.message : "Failed to load trust status";
  }

  const scopedHref = (path: string) => {
    const q = query.toString();
    return q ? `${path}?${q}` : path;
  };

  if (fetchError || !trust) {
    return (
      <div className="space-y-4">
        <h1 className="text-xl font-bold text-slate-900">Trust & Audit</h1>
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
          {fetchError ?? "Trust status unavailable"}
        </div>
      </div>
    );
  }

  const components = Object.entries(trust.trust_components);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-900">Trust & Audit Fabric</h1>
          <p className="text-sm text-slate-500">
            Cryptographic proof of system integrity and decision history
          </p>
        </div>
        <div className="flex gap-2">
          <Link
            href={scopedHref("/audit/evidence")}
            className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50"
          >
            Evidence Graph
          </Link>
          <Link
            href={scopedHref("/audit/export")}
            className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800"
          >
            Export Pack
          </Link>
        </div>
      </div>

      {/* Trust Score */}
      <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
        <div className="flex items-center gap-6">
          <div className="relative h-28 w-28">
            <svg viewBox="0 0 120 120" className="h-28 w-28 -rotate-90">
              <circle
                cx="60" cy="60" r="52"
                fill="none" stroke="#e2e8f0" strokeWidth="10"
              />
              <circle
                cx="60" cy="60" r="52"
                fill="none"
                stroke="currentColor"
                strokeWidth="10"
                strokeLinecap="round"
                strokeDasharray={`${(trust.trust_score / 100) * 327} 327`}
                className={scoreColor(trust.trust_score)}
              />
            </svg>
            <div className="absolute inset-0 flex items-center justify-center">
              <span className={`text-2xl font-bold ${scoreColor(trust.trust_score)}`}>
                {trust.trust_score}
              </span>
            </div>
          </div>
          <div>
            <h2 className="text-lg font-bold text-slate-900">Trust Score</h2>
            <p className="text-sm text-slate-500">
              {trust.trust_score >= 80
                ? "Strong — system integrity is provable"
                : trust.trust_score >= 50
                  ? "Moderate — some trust components need attention"
                  : "Weak — critical trust gaps detected"}
            </p>
          </div>
        </div>

        {/* Component breakdown */}
        <div className="mt-5 grid gap-2">
          {components.map(([key, comp]) => {
            const meta = COMPONENT_LABELS[key] ?? { label: key, description: "" };
            return (
              <div
                key={key}
                className={`flex items-center justify-between rounded-lg border px-4 py-2.5 ${
                  comp.passes
                    ? "border-emerald-200 bg-emerald-50"
                    : "border-rose-200 bg-rose-50"
                }`}
              >
                <div className="flex items-center gap-3">
                  <span className={`text-lg ${comp.passes ? "text-emerald-600" : "text-rose-500"}`}>
                    {comp.passes ? "✓" : "✕"}
                  </span>
                  <div>
                    <p className="text-sm font-medium text-slate-800">{meta.label}</p>
                    <p className="text-xs text-slate-500">{meta.description}</p>
                  </div>
                </div>
                <span className="text-xs font-semibold text-slate-500">{comp.weight} pts</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Status cards grid */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {/* Decisions */}
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
            Decision Audit Trail
          </h3>
          <p className="mt-2 text-2xl font-bold text-slate-900">
            {trust.decisions.total.toLocaleString()}
          </p>
          <p className="text-xs text-slate-500">
            Latest: {formatDate(trust.decisions.latest_at)}
          </p>
        </div>

        {/* Ledger */}
        <div className={`rounded-xl border p-5 shadow-sm ${
          trust.ledger.valid
            ? "border-emerald-200 bg-emerald-50"
            : "border-rose-200 bg-rose-50"
        }`}>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
            Ledger Integrity
          </h3>
          <p className={`mt-2 text-2xl font-bold ${
            trust.ledger.valid ? "text-emerald-700" : "text-rose-700"
          }`}>
            {trust.ledger.valid ? "Valid" : "Broken"}
          </p>
          <p className="text-xs text-slate-500">
            {trust.ledger.checked} chains verified, {trust.ledger.broken_chains} broken
          </p>
        </div>

        {/* Checkpoint */}
        <div className={`rounded-xl border p-5 shadow-sm ${
          trust.checkpoint?.fresh
            ? "border-emerald-200 bg-emerald-50"
            : "border-amber-200 bg-amber-50"
        }`}>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
            Latest Checkpoint
          </h3>
          {trust.checkpoint ? (
            <>
              <p className="mt-2 text-sm font-semibold text-slate-800">
                {trust.checkpoint.period_id}
              </p>
              <p className="text-xs text-slate-500">
                {trust.checkpoint.event_count} events |{" "}
                {trust.checkpoint.signed ? "Signed" : "Unsigned"} |{" "}
                {trust.checkpoint.fresh ? "Fresh" : "Stale"}
              </p>
              <p className="mt-1 font-mono text-[10px] text-slate-400 truncate">
                root: {trust.checkpoint.root_hash?.slice(0, 24)}...
              </p>
            </>
          ) : (
            <p className="mt-2 text-sm text-slate-500 italic">No checkpoints yet</p>
          )}
        </div>

        {/* External Anchors */}
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
            External Anchors
          </h3>
          <p className="mt-2 text-2xl font-bold text-slate-900">
            {trust.external_anchors.count}
          </p>
          <p className="text-xs text-slate-500">
            Latest: {formatDate(trust.external_anchors.latest_at)}
          </p>
        </div>

        {/* Attestations */}
        <div className={`rounded-xl border p-5 shadow-sm ${
          trust.attestations.compromised === 0
            ? "border-slate-200 bg-white"
            : "border-rose-200 bg-rose-50"
        }`}>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
            Attestations
          </h3>
          <p className="mt-2 text-2xl font-bold text-slate-900">
            {trust.attestations.total}
          </p>
          <p className="text-xs text-slate-500">
            {trust.attestations.compromised === 0
              ? "No compromised keys"
              : `${trust.attestations.compromised} compromised key(s)`}
          </p>
        </div>

        {/* Tamper Evidence */}
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
            Tamper Evidence
          </h3>
          <p className="mt-2 text-2xl font-bold text-emerald-700">
            {trust.tamper_evidence.append_only_tables} tables
          </p>
          <p className="text-xs text-slate-500">
            Append-only with {trust.tamper_evidence.trigger_protection} triggers
          </p>
        </div>
      </div>

      {/* Signal Freshness */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <h3 className="text-sm font-semibold text-slate-800 mb-3">
          Zero-Trust Signal Freshness
        </h3>
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <ConfigItem
            label="Max Age"
            value={`${trust.signal_freshness.max_age_seconds ?? "—"}s`}
          />
          <ConfigItem
            label="Require Timestamp"
            value={trust.signal_freshness.require_computed_at ? "Yes" : "No"}
            good={!!trust.signal_freshness.require_computed_at}
          />
          <ConfigItem
            label="Require Hash"
            value={trust.signal_freshness.require_signal_hash ? "Yes" : "No"}
          />
          <ConfigItem
            label="Fail on Stale"
            value={trust.signal_freshness.fail_on_stale ? "Yes" : "No"}
            good={!!trust.signal_freshness.fail_on_stale}
          />
        </div>
      </div>

      {/* Immutable tables */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <h3 className="text-sm font-semibold text-slate-800 mb-3">
          Append-Only Protected Tables
        </h3>
        <div className="flex flex-wrap gap-2">
          {trust.immutable_tables.map((table) => (
            <span
              key={table}
              className="rounded-md border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs font-mono text-slate-600"
            >
              {table}
            </span>
          ))}
        </div>
        <p className="mt-2 text-xs text-slate-500">
          All tables above are protected by database triggers that prevent UPDATE and DELETE operations.
          Any mutation attempt raises an exception and is logged.
        </p>
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

function ConfigItem({
  label,
  value,
  good,
}: {
  label: string;
  value: string;
  good?: boolean;
}) {
  return (
    <div className="rounded-lg border border-slate-100 px-3 py-2">
      <p className="text-xs text-slate-500">{label}</p>
      <p className={`text-sm font-semibold ${
        good === true ? "text-emerald-700" : good === false ? "text-slate-600" : "text-slate-800"
      }`}>
        {value}
      </p>
    </div>
  );
}
