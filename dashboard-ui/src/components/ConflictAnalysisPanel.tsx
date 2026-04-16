"use client";

import { useEffect, useState } from "react";
import type { ConflictAnalysis } from "@/lib/types";
import { callDashboardApi } from "@/lib/api";

interface Props {
  policyId: string;
  tenantId: string;
}

export function ConflictAnalysisPanel({ policyId, tenantId }: Props) {
  const [analysis, setAnalysis] = useState<ConflictAnalysis | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    callDashboardApi<{ analysis: ConflictAnalysis }>(
      `/api/dashboard/policies/${policyId}/conflicts?tenant_id=${encodeURIComponent(tenantId)}`,
    )
      .then((data) => setAnalysis(data.analysis))
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load"))
      .finally(() => setLoading(false));
  }, [policyId, tenantId]);

  if (loading) {
    return <div className="animate-pulse rounded-lg bg-slate-100 h-32" />;
  }

  if (error) {
    return (
      <div className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
        {error}
      </div>
    );
  }

  if (!analysis) return null;

  const { summary } = analysis;
  const totalIssues =
    summary.contradiction_count + summary.shadowed_rule_count + summary.coverage_gap_count + summary.warning_count;

  if (analysis.ok && totalIssues === 0) {
    return (
      <div className="flex items-center gap-2 rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3">
        <span className="text-emerald-600 text-lg">✓</span>
        <span className="text-sm font-medium text-emerald-800">
          No conflicts, shadowing, or coverage gaps detected
        </span>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Summary cards */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <SummaryCard label="Contradictions" count={summary.contradiction_count} color="rose" />
        <SummaryCard label="Shadowed Rules" count={summary.shadowed_rule_count} color="amber" />
        <SummaryCard label="Coverage Gaps" count={summary.coverage_gap_count} color="orange" />
        <SummaryCard label="Warnings" count={summary.warning_count} color="slate" />
      </div>

      {/* Contradiction details */}
      {analysis.contradictions.length > 0 && (
        <IssueSection
          title="Contradictions"
          description="Rules that produce conflicting outcomes for the same input"
          items={analysis.contradictions}
          color="rose"
        />
      )}

      {/* Shadowed rules */}
      {analysis.shadowed_rules.length > 0 && (
        <IssueSection
          title="Shadowed Rules"
          description="Rules that can never fire because a higher-priority rule always matches first"
          items={analysis.shadowed_rules}
          color="amber"
        />
      )}

      {/* Coverage gaps */}
      {analysis.coverage_gaps.length > 0 && (
        <IssueSection
          title="Coverage Gaps"
          description="Transitions or conditions with no matching policy rule"
          items={analysis.coverage_gaps}
          color="orange"
        />
      )}

      {/* Warnings */}
      {analysis.warnings.length > 0 && (
        <IssueSection
          title="Warnings"
          description="Non-blocking issues that may indicate misconfiguration"
          items={analysis.warnings}
          color="slate"
        />
      )}
    </div>
  );
}

function SummaryCard({
  label,
  count,
  color,
}: {
  label: string;
  count: number;
  color: string;
}) {
  const colorMap: Record<string, string> = {
    rose: count > 0 ? "border-rose-200 bg-rose-50" : "border-slate-100 bg-white",
    amber: count > 0 ? "border-amber-200 bg-amber-50" : "border-slate-100 bg-white",
    orange: count > 0 ? "border-orange-200 bg-orange-50" : "border-slate-100 bg-white",
    slate: "border-slate-100 bg-white",
  };

  const textMap: Record<string, string> = {
    rose: count > 0 ? "text-rose-700" : "text-slate-400",
    amber: count > 0 ? "text-amber-700" : "text-slate-400",
    orange: count > 0 ? "text-orange-700" : "text-slate-400",
    slate: "text-slate-600",
  };

  return (
    <div className={`rounded-lg border px-3 py-2 ${colorMap[color]}`}>
      <p className={`text-2xl font-bold ${textMap[color]}`}>{count}</p>
      <p className="text-xs text-slate-500">{label}</p>
    </div>
  );
}

function IssueSection({
  title,
  description,
  items,
  color,
}: {
  title: string;
  description: string;
  items: Array<{ code: string; message: string; severity: string }>;
  color: string;
}) {
  const borderMap: Record<string, string> = {
    rose: "border-rose-200",
    amber: "border-amber-200",
    orange: "border-orange-200",
    slate: "border-slate-200",
  };

  return (
    <div>
      <h4 className="text-sm font-semibold text-slate-800">{title}</h4>
      <p className="text-xs text-slate-500 mb-2">{description}</p>
      <ul className="space-y-2">
        {items.map((item, i) => (
          <li key={i} className={`rounded-lg border bg-white px-4 py-3 ${borderMap[color]}`}>
            <span className="text-xs font-mono font-semibold text-slate-600">{item.code}</span>
            <p className="mt-1 text-sm text-slate-700">{item.message}</p>
          </li>
        ))}
      </ul>
    </div>
  );
}
