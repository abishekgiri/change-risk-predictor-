"use client";

import { useMemo, useState } from "react";

import { CopyButton } from "@/components/CopyButton";
import type { DecisionExplainer } from "@/lib/types";

type Tab = "risk" | "signals" | "evaluation";

interface DecisionExplainTabsProps {
  risk: DecisionExplainer["risk"];
  signals: DecisionExplainer["signals"];
  evaluationTree: DecisionExplainer["evaluation_tree"];
}

export function DecisionExplainTabs({
  risk,
  signals,
  evaluationTree,
}: DecisionExplainTabsProps) {
  const [activeTab, setActiveTab] = useState<Tab>("risk");

  const sortedComponents = useMemo(() => {
    return [...risk.components].sort((a, b) => {
      const lhs = typeof a.weight === "number" ? a.weight : Number.NEGATIVE_INFINITY;
      const rhs = typeof b.weight === "number" ? b.weight : Number.NEGATIVE_INFINITY;
      if (rhs !== lhs) return rhs - lhs;
      return String(a.name || "").localeCompare(String(b.name || ""));
    });
  }, [risk.components]);

  const evaluationJson = useMemo(() => JSON.stringify(evaluationTree, null, 2), [evaluationTree]);

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <div className="flex flex-wrap gap-2">
        {([
          { key: "risk", label: "Risk" },
          { key: "signals", label: "Signals" },
          { key: "evaluation", label: "Evaluation tree" },
        ] as const).map((tab) => (
          <button
            key={tab.key}
            type="button"
            onClick={() => setActiveTab(tab.key)}
            className={`rounded-md px-3 py-1.5 text-sm ${
              activeTab === tab.key
                ? "bg-slate-900 text-white"
                : "border border-slate-200 bg-white text-slate-700 hover:bg-slate-50"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === "risk" ? (
        <div className="mt-4 space-y-4">
          <div className="rounded-lg border border-slate-100 bg-slate-50 p-3">
            <p className="text-xs uppercase tracking-wide text-slate-500">Risk score</p>
            <p className="text-2xl font-semibold text-slate-900">{risk.score.toFixed(3)}</p>
          </div>
          <div className="overflow-x-auto">
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
                {sortedComponents.map((component, index) => (
                  <tr key={`${component.name}-${index}`} className="border-b border-slate-100">
                    <td className="py-2 pr-2">{component.name}</td>
                    <td className="py-2 pr-2 font-mono text-xs">{String(component.value)}</td>
                    <td className="py-2 pr-2">{component.weight ?? "-"}</td>
                    <td className="py-2 pr-2">{component.notes || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}

      {activeTab === "signals" ? (
        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
                <th className="py-2 pr-2 text-left">Name</th>
                <th className="py-2 pr-2 text-left">Value</th>
                <th className="py-2 pr-2 text-left">Source</th>
                <th className="py-2 pr-2 text-left">Confidence</th>
                <th className="py-2 pr-2 text-left">Captured at</th>
              </tr>
            </thead>
            <tbody>
              {signals.map((signal) => (
                <tr key={`${signal.name}-${signal.captured_at || "na"}`} className="border-b border-slate-100">
                  <td className="py-2 pr-2">{signal.name}</td>
                  <td className="py-2 pr-2 font-mono text-xs">{JSON.stringify(signal.value)}</td>
                  <td className="py-2 pr-2">{signal.source || "-"}</td>
                  <td className="py-2 pr-2">{signal.confidence ?? "-"}</td>
                  <td className="py-2 pr-2">{signal.captured_at || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {activeTab === "evaluation" ? (
        <div className="mt-4 space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-sm text-slate-600">Evaluation graph payload used for explainability.</p>
            <CopyButton value={evaluationJson} label="Copy evaluation JSON" />
          </div>
          <details className="rounded-lg border border-slate-100 bg-slate-50 p-3" open>
            <summary className="cursor-pointer text-sm font-medium text-slate-700">View evaluation JSON</summary>
            <pre className="mt-3 overflow-x-auto text-xs text-slate-700">{evaluationJson}</pre>
          </details>
        </div>
      ) : null}
    </div>
  );
}
