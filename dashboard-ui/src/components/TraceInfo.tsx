import React from "react";

export function TraceInfo({ traceId }: { traceId?: string | null }) {
  if (!traceId) {
    return null;
  }
  return (
    <p className="text-xs text-slate-500">
      trace_id: <span className="font-mono text-slate-700">{traceId}</span>
    </p>
  );
}
