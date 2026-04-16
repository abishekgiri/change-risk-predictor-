"use client";

import type { PolicyScopeType } from "@/lib/types";

interface LineageEntry {
  policy_id: string;
  version: number;
  scope_id: string;
  policy_hash: string;
}

interface Props {
  lineage: Record<string, LineageEntry>;
  currentScope: PolicyScopeType;
}

const SCOPE_ORDER: PolicyScopeType[] = ["org", "project", "workflow", "transition"];

const SCOPE_COLORS: Record<PolicyScopeType, { bg: string; border: string; text: string; ring: string }> = {
  org: { bg: "bg-indigo-50", border: "border-indigo-300", text: "text-indigo-800", ring: "ring-indigo-400" },
  project: { bg: "bg-sky-50", border: "border-sky-300", text: "text-sky-800", ring: "ring-sky-400" },
  workflow: { bg: "bg-violet-50", border: "border-violet-300", text: "text-violet-800", ring: "ring-violet-400" },
  transition: { bg: "bg-fuchsia-50", border: "border-fuchsia-300", text: "text-fuchsia-800", ring: "ring-fuchsia-400" },
};

export function InheritanceChain({ lineage, currentScope }: Props) {
  if (!lineage || Object.keys(lineage).length === 0) {
    return (
      <p className="text-sm text-slate-500 italic">
        No inheritance chain — this policy is standalone.
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-0">
      {SCOPE_ORDER.map((scope, idx) => {
        const entry = lineage[scope];
        const isCurrent = scope === currentScope;
        const colors = SCOPE_COLORS[scope];
        const isLast = idx === SCOPE_ORDER.length - 1 || !SCOPE_ORDER.slice(idx + 1).some((s) => lineage[s]);

        return (
          <div key={scope} className="flex items-start gap-3">
            {/* Vertical connector */}
            <div className="flex flex-col items-center">
              <div
                className={`h-8 w-8 rounded-full border-2 flex items-center justify-center text-xs font-bold ${
                  entry
                    ? `${colors.bg} ${colors.border} ${colors.text}`
                    : "bg-slate-50 border-slate-200 text-slate-400"
                } ${isCurrent ? `ring-2 ${colors.ring}` : ""}`}
              >
                {scope[0].toUpperCase()}
              </div>
              {!isLast && (
                <div className={`w-0.5 h-6 ${entry ? "bg-slate-300" : "bg-slate-100"}`} />
              )}
            </div>

            {/* Content */}
            <div className="pt-1 min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                  {scope}
                </span>
                {isCurrent && (
                  <span className="rounded bg-slate-900 px-1.5 py-0.5 text-[10px] font-semibold text-white">
                    CURRENT
                  </span>
                )}
                {entry && !isCurrent && (
                  <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] font-medium text-slate-600">
                    INHERITED
                  </span>
                )}
              </div>
              {entry ? (
                <div className="mt-0.5 flex items-center gap-2 text-xs text-slate-600">
                  <span className="font-mono">{entry.scope_id}</span>
                  <span className="text-slate-300">|</span>
                  <span>v{entry.version}</span>
                  <span className="text-slate-300">|</span>
                  <span className="font-mono text-[10px] text-slate-400">
                    {entry.policy_hash.slice(0, 8)}
                  </span>
                </div>
              ) : (
                <p className="mt-0.5 text-xs text-slate-400 italic">No policy at this scope</p>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
