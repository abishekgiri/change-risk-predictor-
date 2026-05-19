import Link from "next/link";
import { resolveDashboardScope, scopeToQuery } from "@/lib/dashboard-scope";

export const dynamic = "force-dynamic";

interface SettingsPageProps {
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
}

// Single landing for tenant administration, onboarding, and billing.
// These used to be top-level nav items; folded here as part of the
// nav-five reduction.
export default async function SettingsPage({ searchParams }: SettingsPageProps) {
  const params = await searchParams;
  const scope = resolveDashboardScope(params);
  const query = scopeToQuery(scope);
  const qs = query ? `?${query}` : "";

  const sections = [
    {
      title: "Tenant",
      description: "Tenant identity, signing keys, integration credentials, and per-tenant policy bindings.",
      cta: "Open tenant settings",
      href: `/tenant${qs}`,
    },
    {
      title: "Onboarding",
      description: "Connect Jira and GitHub, run a simulation, enable canary mode.",
      cta: "Open onboarding",
      href: `/onboarding${qs}`,
    },
    {
      title: "Billing",
      description: "Plan, seat count, invoices, and contract status.",
      cta: "Open billing",
      href: `/billing${qs}`,
    },
  ];

  return (
    <div className="space-y-6">
      <header className="space-y-1">
        <h1 className="text-xl font-bold text-slate-900">Settings</h1>
        <p className="text-sm text-slate-500">Tenant administration, onboarding, and billing.</p>
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
