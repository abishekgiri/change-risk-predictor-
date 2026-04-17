import { Suspense } from "react";
import { DecisionTraceClient } from "./DecisionTraceClient";

export const dynamic = "force-dynamic";

export default function AuditTracePage() {
  return (
    <main className="mx-auto max-w-7xl px-6 py-8">
      <Suspense fallback={<div className="text-sm text-slate-500">Loading trace…</div>}>
        <DecisionTraceClient />
      </Suspense>
    </main>
  );
}
