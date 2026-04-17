import { Suspense } from "react";
import { ProofMetricsClient } from "./ProofMetricsClient";

export const dynamic = "force-dynamic";

export default function ProofPage() {
  return (
    <main className="mx-auto max-w-7xl px-6 py-8">
      <Suspense fallback={<div className="text-sm text-slate-500">Loading proof metrics…</div>}>
        <ProofMetricsClient />
      </Suspense>
    </main>
  );
}
