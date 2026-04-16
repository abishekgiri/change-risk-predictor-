import { Suspense } from "react";
import { CIGateClient } from "./CIGateClient";

export default function CIGatePage() {
  return (
    <Suspense fallback={<div className="animate-pulse rounded-xl bg-slate-100 h-96" />}>
      <CIGateClient />
    </Suspense>
  );
}
