import { Suspense } from "react";
import { PolicySimulateClient } from "./PolicySimulateClient";

export default function PolicySimulatePage() {
  return (
    <Suspense fallback={<div className="animate-pulse rounded-xl bg-slate-100 h-96" />}>
      <PolicySimulateClient />
    </Suspense>
  );
}
