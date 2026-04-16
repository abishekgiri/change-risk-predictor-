"use client";

import { useState } from "react";
import type { RegistryPolicy, PolicyStatus } from "@/lib/types";
import { PolicyLifecycleActions } from "@/components/PolicyLifecycleActions";
import { LintResultsPanel } from "@/components/LintResultsPanel";
import { InheritanceChain } from "@/components/InheritanceChain";
import { ConflictAnalysisPanel } from "@/components/ConflictAnalysisPanel";
import { PolicyEventTimeline } from "@/components/PolicyEventTimeline";
import { HistoricalSimulationPanel } from "@/components/HistoricalSimulationPanel";

type Tab = "overview" | "conflicts" | "simulation" | "history";

interface Props {
  policy: RegistryPolicy;
  tenantId: string;
}

export function PolicyDetailClient({ policy: initialPolicy, tenantId }: Props) {
  const [policy, setPolicy] = useState(initialPolicy);
  const [activeTab, setActiveTab] = useState<Tab>("overview");

  const handleStatusChange = (updated: Record<string, unknown>) => {
    setPolicy((prev) => ({
      ...prev,
      status: (updated.status as PolicyStatus) ?? prev.status,
      activated_at: (updated.activated_at as string) ?? prev.activated_at,
      activated_by: (updated.activated_by as string) ?? prev.activated_by,
    }));
  };

  const tabs: { key: Tab; label: string }[] = [
    { key: "overview", label: "Overview" },
    { key: "conflicts", label: "Conflicts & Coverage" },
    { key: "simulation", label: "Historical Simulation" },
    { key: "history", label: "Event History" },
  ];

  return (
    <div className="space-y-6">
      {/* Lifecycle actions */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <h3 className="text-sm font-semibold text-slate-800 mb-3">Lifecycle Actions</h3>
        <PolicyLifecycleActions
          policyId={policy.policy_id}
          tenantId={tenantId}
          currentStatus={policy.status}
          onStatusChange={handleStatusChange}
        />
      </div>

      {/* Tab navigation */}
      <div className="flex gap-1 border-b border-slate-200">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
              activeTab === tab.key
                ? "border-slate-900 text-slate-900"
                : "border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {activeTab === "overview" && (
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Lint results */}
          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <h3 className="text-sm font-semibold text-slate-800 mb-3">Lint Results</h3>
            <LintResultsPanel
              errors={policy.lint_errors ?? []}
              warnings={policy.lint_warnings ?? []}
            />
          </div>

          {/* Inheritance chain */}
          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <h3 className="text-sm font-semibold text-slate-800 mb-3">Inheritance Chain</h3>
            <p className="text-xs text-slate-500 mb-3">
              Shows how this policy fits in the scope hierarchy and what it inherits from.
            </p>
            <InheritanceChain
              lineage={{
                [policy.scope_type]: {
                  policy_id: policy.policy_id,
                  version: policy.version,
                  scope_id: policy.scope_id,
                  policy_hash: policy.policy_hash,
                },
              }}
              currentScope={policy.scope_type}
            />
          </div>
        </div>
      )}

      {activeTab === "conflicts" && (
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <h3 className="text-sm font-semibold text-slate-800 mb-3">
            Conflict & Coverage Analysis
          </h3>
          <p className="text-xs text-slate-500 mb-4">
            Checks for contradictions, shadowed rules, and uncovered transitions.
          </p>
          <ConflictAnalysisPanel policyId={policy.policy_id} tenantId={tenantId} />
        </div>
      )}

      {activeTab === "simulation" && (
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <h3 className="text-sm font-semibold text-slate-800 mb-3">Historical What-If</h3>
          <p className="text-xs text-slate-500 mb-4">
            Replay past decisions against this policy to see what would have changed.
          </p>
          <HistoricalSimulationPanel
            tenantId={tenantId}
            policyId={policy.policy_id}
          />
        </div>
      )}

      {activeTab === "history" && (
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <h3 className="text-sm font-semibold text-slate-800 mb-3">Event Timeline</h3>
          <PolicyEventTimeline policyId={policy.policy_id} tenantId={tenantId} />
        </div>
      )}
    </div>
  );
}
