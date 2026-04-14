import React from "react";

import { SeverityBadge } from "@/components/SeverityBadge";
import { formatDetailValue } from "@/lib/clarity";
import type { Severity } from "@/lib/types";

type DisplaySeverity = Severity | "unknown";

function normalizeSeverity(value: unknown): DisplaySeverity {
  const raw = String(value || "").trim().toLowerCase();
  if (raw === "high" || raw === "medium" || raw === "low") {
    return raw;
  }
  return "unknown";
}

function formatKey(value: string): string {
  return String(value || "")
    .replace(/[._-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (match) => match.toUpperCase());
}

export function DeltaTable({
  title,
  rows,
}: {
  title: string;
  rows: Array<Record<string, unknown> & { severity?: Severity | "unknown" }>;
}) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <h3 className="text-sm font-semibold text-slate-800">{title}</h3>
      {rows.length === 0 ? (
        <p className="mt-3 text-sm text-slate-500">No deltas.</p>
      ) : (
        <ul className="mt-3 space-y-2">
          {rows.map((row, idx) => (
            <li key={`${title}-${idx}`} className="rounded-lg border border-slate-100 p-3">
              <div className="mb-2 flex items-center justify-between">
                <span className="text-xs font-medium text-slate-500">{String(row.path ?? "-")}</span>
                <SeverityBadge severity={normalizeSeverity(row.severity)} />
              </div>
              <div className="grid gap-2 md:grid-cols-2">
                {Object.entries(row)
                  .filter(([key]) => key !== "severity")
                  .map(([key, value]) => (
                    <div key={key} className="rounded-md bg-slate-50 p-2">
                      <p className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">{formatKey(key)}</p>
                      <p className="mt-1 break-words text-sm text-slate-800">{formatDetailValue(value)}</p>
                    </div>
                  ))}
              </div>
              <details className="mt-3 rounded-md border border-slate-100 bg-white p-2">
                <summary className="cursor-pointer text-xs font-medium text-slate-700">View raw change payload</summary>
                <pre className="mt-2 overflow-x-auto text-xs text-slate-700">{JSON.stringify(row, null, 2)}</pre>
              </details>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
