import { Suspense } from "react";
import { AuditExportClient } from "./AuditExportClient";

export default function AuditExportPage() {
  return (
    <Suspense fallback={<div className="animate-pulse rounded-xl bg-slate-100 h-96" />}>
      <AuditExportClient />
    </Suspense>
  );
}
