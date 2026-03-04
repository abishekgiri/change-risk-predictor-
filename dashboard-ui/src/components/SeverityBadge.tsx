import React from "react";

import type { Severity } from "@/lib/types";

type DisplaySeverity = Severity | "unknown";

const palette: Record<DisplaySeverity, string> = {
  high: "bg-rose-100 text-rose-700 border-rose-200",
  medium: "bg-amber-100 text-amber-700 border-amber-200",
  low: "bg-emerald-100 text-emerald-700 border-emerald-200",
  unknown: "bg-slate-100 text-slate-700 border-slate-200",
};

export function SeverityBadge({ severity }: { severity: DisplaySeverity }) {
  const raw = String(severity || "").toLowerCase();
  const normalized: DisplaySeverity =
    raw === "high" || raw === "medium" || raw === "low" ? raw : "unknown";
  return (
    <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium ${palette[normalized]}`}>
      {normalized.toUpperCase()}
    </span>
  );
}
