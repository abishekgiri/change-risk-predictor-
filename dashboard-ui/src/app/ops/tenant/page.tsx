import { Suspense } from "react";
import { TenantHealthClient } from "./TenantHealthClient";

export const metadata = { title: "Tenant Health — ReleaseGate" };

export default function TenantHealthPage() {
  return (
    <div className="mx-auto max-w-7xl px-6 py-8">
      <Suspense fallback={<div className="text-sm text-slate-500">Loading tenant health…</div>}>
        <TenantHealthClient />
      </Suspense>
    </div>
  );
}
