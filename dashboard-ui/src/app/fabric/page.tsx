import { Suspense } from "react";
import { FabricHealthClient } from "./FabricHealthClient";

export const dynamic = "force-dynamic";

export default function FabricPage() {
  return (
    <main className="mx-auto max-w-7xl px-6 py-8">
      <Suspense fallback={<div className="text-sm text-slate-500">Loading fabric health…</div>}>
        <FabricHealthClient />
      </Suspense>
    </main>
  );
}
