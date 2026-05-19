import { Suspense } from "react";
import { notFound } from "next/navigation";
import { ProofMetricsClient } from "./ProofMetricsClient";

export const dynamic = "force-dynamic";

// /proof is gated behind a feature flag.  It is an internal sales tool
// today, not the customer's product.  Re-enable once we have three real
// customer testimonials to anchor the metrics against.
//
// To enable locally:
//   NEXT_PUBLIC_RELEASEGATE_ENABLE_PROOF=true npm run dev
function isProofEnabled(): boolean {
  const flag = process.env.NEXT_PUBLIC_RELEASEGATE_ENABLE_PROOF;
  return typeof flag === "string" && flag.toLowerCase() === "true";
}

export default function ProofPage() {
  if (!isProofEnabled()) {
    // Surface a 404 instead of a "this page is disabled" notice so that
    // crawlers, link-checkers, and casual prospects don't see a half-baked
    // marketing page.
    notFound();
  }

  return (
    <main className="mx-auto max-w-7xl px-6 py-8">
      <Suspense fallback={<div className="text-sm text-slate-500">Loading proof metrics…</div>}>
        <ProofMetricsClient />
      </Suspense>
    </main>
  );
}
