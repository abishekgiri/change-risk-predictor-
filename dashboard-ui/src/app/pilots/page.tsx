import { Suspense } from "react";
import { PilotTrackerClient } from "./PilotTrackerClient";

export const dynamic = "force-dynamic";

export default function PilotsPage() {
  return (
    <main className="mx-auto max-w-7xl px-6 py-8">
      <Suspense fallback={<div className="text-sm text-slate-500">Loading pilots…</div>}>
        <PilotTrackerClient />
      </Suspense>
    </main>
  );
}
