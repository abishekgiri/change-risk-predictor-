import { Suspense } from "react";
import { OpsSystemHealthClient } from "./OpsSystemHealthClient";

export const metadata = { title: "Ops Health — ReleaseGate" };

export default function OpsPage() {
  return (
    <div className="mx-auto max-w-7xl px-6 py-8">
      <Suspense fallback={<div className="text-sm text-slate-500">Loading ops health…</div>}>
        <OpsSystemHealthClient />
      </Suspense>
    </div>
  );
}
