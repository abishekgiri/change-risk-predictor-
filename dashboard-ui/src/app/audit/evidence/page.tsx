import { Suspense } from "react";
import { EvidenceSearchClient } from "./EvidenceSearchClient";

export default function EvidenceGraphPage() {
  return (
    <Suspense fallback={<div className="animate-pulse rounded-xl bg-slate-100 h-96" />}>
      <EvidenceSearchClient />
    </Suspense>
  );
}
