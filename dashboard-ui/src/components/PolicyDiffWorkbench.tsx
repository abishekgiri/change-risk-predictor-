"use client";

import { useMemo, useState } from "react";

import { DeltaTable } from "@/components/DeltaTable";
import { SeverityBadge } from "@/components/SeverityBadge";
import { TraceInfo } from "@/components/TraceInfo";
import { callDashboardApi } from "@/lib/api";
import type { PolicyDiffResponse, Severity } from "@/lib/types";

const EMPTY_POLICY = JSON.stringify(
  {
    strict_fail_closed: true,
    approval_requirements: { min_approvals: 2, required_roles: ["security", "em"] },
    risk_thresholds: { prod: { max_score: 0.7 } },
    transition_rules: [{ rule_id: "prod-block", transition_id: "31", environment: "prod", result: "BLOCK" }],
  },
  null,
  2,
);

const EMPTY_CANDIDATE = JSON.stringify(
  {
    strict_fail_closed: false,
    approval_requirements: { min_approvals: 1, required_roles: ["security"] },
    risk_thresholds: { prod: { max_score: 0.9 } },
    transition_rules: [{ rule_id: "prod-block", transition_id: "31", environment: "prod", result: "ALLOW" }],
  },
  null,
  2,
);

type Tab = "thresholds" | "conditions" | "roles" | "sod";
type SeverityFilter = "all" | Severity;
type DisplaySeverity = Severity | "unknown";
type DiffRow = Record<string, unknown> & { severity?: unknown };

const TAB_LABELS: Record<Tab, string> = {
  thresholds: "Thresholds",
  conditions: "Conditions",
  roles: "Roles",
  sod: "SoD",
};

function normalizeSeverity(value: unknown): DisplaySeverity {
  const raw = String(value || "").trim().toLowerCase();
  if (raw === "high" || raw === "medium" || raw === "low") {
    return raw;
  }
  return "unknown";
}

function matchesSeverityFilter(severity: DisplaySeverity, filter: SeverityFilter): boolean {
  if (filter === "all") return true;
  return severity === filter;
}

function tabRowsFromResult(result: PolicyDiffResponse, tab: Tab): DiffRow[] {
  if (tab === "thresholds") return result.threshold_deltas as DiffRow[];
  if (tab === "conditions") return result.condition_deltas as DiffRow[];
  if (tab === "roles") return result.role_deltas as DiffRow[];
  return result.sod_deltas as DiffRow[];
}

function extractPath(row: DiffRow): string | null {
  const candidates = [
    row.path,
    row.json_path,
    row.pointer,
    row.metric_path,
  ];
  for (const candidate of candidates) {
    const value = String(candidate || "").trim();
    if (value) return value;
  }
  return null;
}

function sanitizeSegment(value: string): string {
  return value.trim().replace(/[^a-zA-Z0-9_-]+/g, "-").replace(/^-+|-+$/g, "") || "na";
}

function buildExportFileName(tenantId: string, fromTs?: string | null, toTs?: string | null): string {
  if (fromTs && toTs) {
    return `policy-diff_${sanitizeSegment(tenantId)}_${sanitizeSegment(fromTs)}_${sanitizeSegment(toTs)}.json`;
  }
  return `policy-diff_${sanitizeSegment(tenantId)}_${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
}

export function PolicyDiffWorkbench({
  tenantId,
  fromTs = null,
  toTs = null,
}: {
  tenantId: string;
  fromTs?: string | null;
  toTs?: string | null;
}) {
  const [currentPolicyJson, setCurrentPolicyJson] = useState(EMPTY_POLICY);
  const [candidatePolicyJson, setCandidatePolicyJson] = useState(EMPTY_CANDIDATE);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PolicyDiffResponse | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>("thresholds");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");

  const tabRows = useMemo(() => {
    if (!result) return [];
    return tabRowsFromResult(result, activeTab);
  }, [activeTab, result]);

  const filteredRows = useMemo(
    () => tabRows.filter((row) => matchesSeverityFilter(normalizeSeverity(row.severity), severityFilter)),
    [tabRows, severityFilter],
  );

  const visibleSummary = useMemo(() => {
    if (!result) {
      return { total: 0, high: 0, medium: 0, low: 0, unknown: 0 };
    }
    const allRows = (
      [
        ...result.threshold_deltas,
        ...result.condition_deltas,
        ...result.role_deltas,
        ...result.sod_deltas,
      ] as DiffRow[]
    ).filter((row) => matchesSeverityFilter(normalizeSeverity(row.severity), severityFilter));

    const counts = { high: 0, medium: 0, low: 0, unknown: 0 };
    for (const row of allRows) {
      counts[normalizeSeverity(row.severity)] += 1;
    }
    return {
      total: allRows.length,
      ...counts,
    };
  }, [result, severityFilter]);

  const copyablePaths = useMemo(() => {
    const unique = new Set<string>();
    for (const row of filteredRows) {
      const path = extractPath(row);
      if (path) unique.add(path);
    }
    return [...unique];
  }, [filteredRows]);

  return (
    <div className="space-y-6">
      <div className="grid gap-4 lg:grid-cols-2">
        <label className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <p className="text-sm font-semibold text-slate-800">Active Policy JSON</p>
          <textarea
            className="mt-3 h-72 w-full rounded-md border border-slate-200 bg-slate-50 p-2 font-mono text-xs"
            value={currentPolicyJson}
            onChange={(event) => setCurrentPolicyJson(event.target.value)}
          />
        </label>

        <label className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <p className="text-sm font-semibold text-slate-800">Staged Policy JSON</p>
          <textarea
            className="mt-3 h-72 w-full rounded-md border border-slate-200 bg-slate-50 p-2 font-mono text-xs"
            value={candidatePolicyJson}
            onChange={(event) => setCandidatePolicyJson(event.target.value)}
          />
        </label>
      </div>

      <div>
        <button
          type="button"
          disabled={loading}
          className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-60"
          onClick={async () => {
            setLoading(true);
            setError(null);
            try {
              const payload = await callDashboardApi<PolicyDiffResponse>("/api/dashboard/policies/diff", {
                method: "POST",
                body: JSON.stringify({
                  tenant_id: tenantId,
                  current_policy_json: JSON.parse(currentPolicyJson),
                  candidate_policy_json: JSON.parse(candidatePolicyJson),
                }),
              });
              setResult(payload);
            } catch (err) {
              setError(err instanceof Error ? err.message : "Failed to compute policy diff.");
            } finally {
              setLoading(false);
            }
          }}
        >
          {loading ? "Comparing..." : "Compare Policies"}
        </button>
      </div>

      {error ? <p className="text-sm text-rose-700">{error}</p> : null}

      {result ? (
        <>
          <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
            <div className="flex items-center justify-between gap-2">
              <p className="text-sm font-semibold text-slate-800">Summary</p>
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  className="rounded-md border border-slate-200 px-2 py-1 text-xs text-slate-700 hover:bg-slate-50"
                  onClick={() => {
                    const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
                    const href = URL.createObjectURL(blob);
                    const anchor = document.createElement("a");
                    anchor.href = href;
                    anchor.download = buildExportFileName(tenantId, fromTs, toTs);
                    document.body.appendChild(anchor);
                    anchor.click();
                    anchor.remove();
                    URL.revokeObjectURL(href);
                  }}
                >
                  Export JSON
                </button>
                <TraceInfo traceId={result.trace_id} />
              </div>
            </div>
            <div className="mt-3 flex items-center gap-4 text-sm text-slate-700">
              <span>
                {visibleSummary.total} visible changes • {result.overall}
              </span>
              <span className="flex items-center gap-1">
                <SeverityBadge severity={"high" satisfies Severity} /> {visibleSummary.high}
              </span>
              <span className="flex items-center gap-1">
                <SeverityBadge severity={"medium" satisfies Severity} /> {visibleSummary.medium}
              </span>
              <span className="flex items-center gap-1">
                <SeverityBadge severity={"low" satisfies Severity} /> {visibleSummary.low}
              </span>
              {visibleSummary.unknown > 0 ? (
                <span className="flex items-center gap-1">
                  <SeverityBadge severity="unknown" /> {visibleSummary.unknown}
                </span>
              ) : null}
            </div>
            <ul className="mt-3 list-disc space-y-1 pl-5 text-sm text-slate-700">
              {result.summary.summary_bullets.map((bullet, idx) => (
                <li key={`${idx}-${bullet}`}>{bullet}</li>
              ))}
            </ul>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {(["thresholds", "conditions", "roles", "sod"] as const).map((tab) => (
              <button
                key={tab}
                type="button"
                className={`rounded-md px-3 py-1.5 text-sm ${
                  tab === activeTab
                    ? "bg-slate-900 text-white"
                    : "border border-slate-200 bg-white text-slate-700 hover:bg-slate-50"
                }`}
                onClick={() => setActiveTab(tab)}
              >
                {TAB_LABELS[tab]}
              </button>
            ))}
            <span className="ml-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Severity</span>
            {(["all", "high", "medium", "low"] as const).map((filter) => (
              <button
                key={filter}
                type="button"
                className={`rounded-full px-3 py-1 text-xs font-medium ${
                  severityFilter === filter
                    ? "bg-slate-900 text-white"
                    : "border border-slate-200 bg-white text-slate-700 hover:bg-slate-50"
                }`}
                onClick={() => setSeverityFilter(filter)}
              >
                {filter === "all" ? "All" : filter[0].toUpperCase() + filter.slice(1)}
              </button>
            ))}
            <button
              type="button"
              className="ml-auto rounded-md border border-slate-200 px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50"
              onClick={async () => {
                if (!copyablePaths.length) {
                  setCopyState("failed");
                  setTimeout(() => setCopyState("idle"), 1500);
                  return;
                }
                try {
                  await navigator.clipboard.writeText(copyablePaths.join("\n"));
                  setCopyState("copied");
                } catch {
                  setCopyState("failed");
                }
                setTimeout(() => setCopyState("idle"), 1500);
              }}
            >
              {copyState === "copied" ? "Copied!" : copyState === "failed" ? "No paths" : "Copy paths"}
            </button>
          </div>

          <DeltaTable title={`Policy Deltas: ${TAB_LABELS[activeTab]}`} rows={filteredRows as Array<Record<string, unknown> & { severity?: Severity | "unknown" }>} />
        </>
      ) : null}
    </div>
  );
}
