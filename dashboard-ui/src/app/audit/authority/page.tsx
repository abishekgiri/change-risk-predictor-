import { Suspense } from "react";
import { AuthorityReportClient } from "./AuthorityReportClient";

export const metadata = { title: "Authority Report — ReleaseGate" };

export default function AuthorityPage() {
  return (
    <div className="mx-auto max-w-7xl px-6 py-8">
      <Suspense fallback={<div className="text-sm text-slate-500">Loading authority report…</div>}>
        <AuthorityReportClient />
      </Suspense>
    </div>
  );
}
