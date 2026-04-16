"use client";

import { useState } from "react";
import type { LintIssue } from "@/lib/types";

interface Props {
  errors: LintIssue[];
  warnings: LintIssue[];
}

const ISSUE_ICONS: Record<string, string> = {
  CONTRADICTORY_RULES: "Conflict",
  TRANSITION_UNCOVERED: "Gap",
  SHADOWED_RULE: "Shadow",
  DUPLICATE_RULE: "Duplicate",
  UNREACHABLE_CONDITION: "Dead code",
};

export function LintResultsPanel({ errors, warnings }: Props) {
  const [showWarnings, setShowWarnings] = useState(true);
  const allClean = errors.length === 0 && warnings.length === 0;

  if (allClean) {
    return (
      <div className="flex items-center gap-2 rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3">
        <span className="text-emerald-600 text-lg">✓</span>
        <span className="text-sm font-medium text-emerald-800">
          Policy passes all lint checks
        </span>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Summary bar */}
      <div className="flex items-center gap-4">
        {errors.length > 0 && (
          <span className="flex items-center gap-1.5 rounded-md bg-rose-50 border border-rose-200 px-2.5 py-1 text-xs font-semibold text-rose-700">
            {errors.length} error{errors.length !== 1 ? "s" : ""}
          </span>
        )}
        {warnings.length > 0 && (
          <button
            onClick={() => setShowWarnings(!showWarnings)}
            className="flex items-center gap-1.5 rounded-md bg-amber-50 border border-amber-200 px-2.5 py-1 text-xs font-semibold text-amber-700 hover:bg-amber-100"
          >
            {warnings.length} warning{warnings.length !== 1 ? "s" : ""}
            <span className="text-[10px]">{showWarnings ? "▼" : "▶"}</span>
          </button>
        )}
      </div>

      {/* Error list */}
      {errors.length > 0 && (
        <ul className="space-y-2">
          {errors.map((issue, i) => (
            <li
              key={`err-${i}`}
              className="rounded-lg border border-rose-200 bg-white px-4 py-3"
            >
              <div className="flex items-start gap-2">
                <span className="mt-0.5 flex h-5 w-5 items-center justify-center rounded-full bg-rose-100 text-[10px] font-bold text-rose-600">
                  !
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-semibold text-rose-700">
                      {issue.code}
                    </span>
                    {ISSUE_ICONS[issue.code] && (
                      <span className="rounded bg-rose-50 px-1.5 py-0.5 text-[10px] text-rose-500">
                        {ISSUE_ICONS[issue.code]}
                      </span>
                    )}
                  </div>
                  <p className="mt-1 text-sm text-slate-700">{issue.message}</p>
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}

      {/* Warning list */}
      {showWarnings && warnings.length > 0 && (
        <ul className="space-y-2">
          {warnings.map((issue, i) => (
            <li
              key={`warn-${i}`}
              className="rounded-lg border border-amber-200 bg-white px-4 py-3"
            >
              <div className="flex items-start gap-2">
                <span className="mt-0.5 flex h-5 w-5 items-center justify-center rounded-full bg-amber-100 text-[10px] font-bold text-amber-600">
                  ⚠
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-semibold text-amber-700">
                      {issue.code}
                    </span>
                    {ISSUE_ICONS[issue.code] && (
                      <span className="rounded bg-amber-50 px-1.5 py-0.5 text-[10px] text-amber-500">
                        {ISSUE_ICONS[issue.code]}
                      </span>
                    )}
                  </div>
                  <p className="mt-1 text-sm text-slate-700">{issue.message}</p>
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
