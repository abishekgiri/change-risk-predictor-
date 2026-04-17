import { Suspense } from "react";
import { ChangeTraceClient } from "./ChangeTraceClient";

export const dynamic = "force-dynamic";

export default function ChangeTracePage() {
  return (
    <main className="mx-auto max-w-7xl px-6 py-8">
      <Suspense fallback={<div className="text-sm text-slate-500">Loading change trace…</div>}>
        <ChangeTraceClient />
      </Suspense>
    </main>
  );
}
