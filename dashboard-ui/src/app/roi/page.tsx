import { Suspense } from "react";
import { ROICalculatorClient } from "./ROICalculatorClient";

export const dynamic = "force-dynamic";

export default function ROIPage() {
  return (
    <main className="mx-auto max-w-7xl px-6 py-8">
      <Suspense fallback={<div className="text-sm text-slate-500">Loading…</div>}>
        <ROICalculatorClient />
      </Suspense>
    </main>
  );
}
