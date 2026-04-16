import { Suspense } from "react";
import { DecisionTraceClient } from "./DecisionTraceClient";

export const metadata = { title: "Decision Trace — ReleaseGate" };

export default function DecisionTracePage() {
  return (
    <div className="mx-auto max-w-7xl px-6 py-8">
      <Suspense fallback={<div className="text-sm text-slate-500">Loading trace…</div>}>
        <DecisionTraceClient />
      </Suspense>
    </div>
  );
}
