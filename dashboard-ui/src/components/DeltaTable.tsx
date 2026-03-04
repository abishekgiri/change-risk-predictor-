import React from "react";

import { SeverityBadge } from "@/components/SeverityBadge";
import type { Severity } from "@/lib/types";

export function DeltaTable({
  title,
  rows,
}: {
  title: string;
  rows: Array<Record<string, unknown> & { severity: Severity }>;
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
                <SeverityBadge severity={row.severity} />
              </div>
              <pre className="overflow-x-auto rounded-md bg-slate-50 p-2 text-xs text-slate-700">
                {JSON.stringify(row, null, 2)}
              </pre>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
