import Link from "next/link";
import { resolveDashboardScope, scopeToQuery } from "@/lib/dashboard-scope";

export const dynamic = "force-dynamic";

interface EvidencePageProps {
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
}

// Single landing for everything an auditor or operator will want:
//   - Ledger integrity status (binary VERIFIED / FAILED)
//   - Evidence Pack export (PDF + JSON bundle)
//   - Evidence graph (cross-system correlation chain)
//
// Sub-pages still exist at /audit, /audit/export, /audit/evidence; this
// page is the single entry point and is what /evidence in the top nav
// resolves to.
export default async function EvidencePage({ searchParams }: EvidencePageProps) {
  const params = await searchParams;
  const scope = resolveDashboardScope(params);
  const query = scopeToQuery(scope);
  const qs = query ? `?${query}` : "";

  const sections = [
    {
      title: "Ledger integrity",
      description:
        "Cryptographic proof that no audit row has been altered. Binary VERIFIED / FAILED indicator backed by the hash-chain check on audit_decisions and the signed-checkpoint chain on audit_attestations.",
      cta: "Open integrity status",
      href: `/audit${qs}`,
    },
    {
      title: "Evidence pack",
      description:
        "One-click PDF + JSON bundle for a given window, mapped to SOC 2 CC8.1. Download and hand to an auditor.",
      cta: "Export evidence pack",
      href: `/audit/export${qs}`,
    },
    {
      title: "Evidence graph",
      description:
        "Cross-system chain: every decision linked to its PR, deploy, change ticket, and incident. Useful for replay and for showing the full lineage of a specific decision.",
      cta: "View evidence graph",
      href: `/audit/evidence${qs}`,
    },
  ];

  return (
    <div className="space-y-6">
      <header className="space-y-1">
        <h1 className="text-xl font-bold text-slate-900">Evidence</h1>
        <p className="text-sm text-slate-500">
          Auditor-ready proof that every change was approved, reviewed, and safe.
        </p>
      </header>

      <div className="grid gap-4 md:grid-cols-3">
        {sections.map((section) => (
          <Link
            key={section.title}
            href={section.href}
            className="group flex flex-col justify-between rounded-xl border border-slate-200 bg-white p-5 shadow-sm transition hover:border-slate-400 hover:shadow-md"
          >
            <div className="space-y-2">
              <h2 className="text-base font-semibold text-slate-900">{section.title}</h2>
              <p className="text-sm leading-relaxed text-slate-600">{section.description}</p>
            </div>
            <span className="mt-4 inline-block text-sm font-semibold text-slate-700 group-hover:text-slate-900">
              {section.cta} →
            </span>
          </Link>
        ))}
      </div>
    </div>
  );
}
