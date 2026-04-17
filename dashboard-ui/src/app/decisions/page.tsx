import { Suspense } from "react";
import { DecisionRegistryClient } from "./DecisionRegistryClient";

export const metadata = { title: "Decision Registry — ReleaseGate" };

export default function DecisionsPage() {
  return (
    <div className="mx-auto max-w-7xl px-6 py-8">
      <Suspense fallback={<div className="text-sm text-slate-500">Loading decisions…</div>}>
        <DecisionRegistryClient />
      </Suspense>
    </div>
  );
}
