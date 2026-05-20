"use client";

import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useMemo, useState, useTransition } from "react";

import {
  inferRangePreset,
  presetWindow,
  scopeParamsFromSearch,
  type DashboardRangePreset,
} from "@/lib/dashboard-scope";

// Top-level navigation is intentionally limited to five items.
// Sub-flows live as tabs/buttons inside their parent page (e.g. policy
// simulate + ci-gate are reachable from /policies; audit-export and
// the evidence graph are reachable from /evidence; tenant/billing/
// onboarding live under /settings).  Hidden routes are still
// reachable by direct URL — they are just not nav-promoted.
const links = [
  { href: "/overview", label: "Overview" },
  { href: "/decisions", label: "Decisions" },
  { href: "/policies", label: "Policies" },
  { href: "/evidence", label: "Evidence" },
  { href: "/settings", label: "Settings" },
];

// Public, unauthenticated routes must not show the tenant/date-range
// chrome — they're linked from cold emails and demo decks, not from
// inside the product.  Each public page renders its own minimal header.
const PUBLIC_ROUTES = ["/trust"];

export function AppNav() {
  const pathname = usePathname();
  const router = useRouter();
  const searchParams = useSearchParams();
  const [isPending, startTransition] = useTransition();

  const currentTenant = searchParams.get("tenant_id") || "";
  const currentFrom = searchParams.get("from");
  const currentTo = searchParams.get("to");
  const currentPreset = inferRangePreset(currentFrom, currentTo);

  const [tenantDraft, setTenantDraft] = useState(currentTenant);
  const [rangePreset, setRangePreset] = useState<DashboardRangePreset>(currentPreset);

  useEffect(() => {
    setTenantDraft(currentTenant);
  }, [currentTenant]);

  useEffect(() => {
    setRangePreset(currentPreset);
  }, [currentPreset]);

  const scopedParams = useMemo(() => scopeParamsFromSearch(searchParams), [searchParams]);

  const scopedHref = (href: string) => {
    const params = new URLSearchParams(scopedParams.toString());
    const query = params.toString();
    return query ? `${href}?${query}` : href;
  };

  const applyScope = () => {
    const params = new URLSearchParams(searchParams.toString());
    const normalizedTenant = tenantDraft.trim();
    if (normalizedTenant) {
      params.set("tenant_id", normalizedTenant);
    } else {
      params.delete("tenant_id");
    }

    if (rangePreset === "default") {
      params.delete("from");
      params.delete("to");
    } else {
      const window = presetWindow(rangePreset);
      params.set("from", window.fromTs);
      params.set("to", window.toTs);
    }

    const query = params.toString();
    const target = query ? `${pathname}?${query}` : pathname;
    startTransition(() => {
      router.replace(target);
    });
  };

  // Suppress the authenticated chrome on public, unauthenticated pages
  // (e.g. /trust).  All hooks above are still called on every render —
  // we only short-circuit the JSX so the Rules of Hooks are preserved.
  if (pathname && PUBLIC_ROUTES.some((r) => pathname === r || pathname.startsWith(`${r}/`))) {
    return null;
  }

  return (
    <nav className="border-b border-slate-200 bg-white">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-3 px-6 py-3">
        <p className="mr-4 text-sm font-semibold text-slate-900">ReleaseGate</p>
        {links.map((link) => {
          const isActive = pathname === link.href;
          return (
            <Link
              key={link.href}
              href={scopedHref(link.href)}
              aria-current={isActive ? "page" : undefined}
              className={`rounded-md px-2 py-1 text-sm ${
                isActive ? "bg-slate-900 text-white" : "text-slate-700 hover:bg-slate-100"
              }`}
            >
              {link.label}
            </Link>
          );
        })}
        <div className="ml-auto flex flex-wrap items-end gap-2">
          <label className="flex flex-col text-xs font-medium text-slate-600">
            Tenant
            <input
              type="text"
              value={tenantDraft}
              onChange={(event) => setTenantDraft(event.target.value)}
              placeholder="default"
              className="mt-1 w-44 rounded-md border border-slate-300 px-2 py-1.5 text-sm text-slate-900"
            />
          </label>
          <label className="flex flex-col text-xs font-medium text-slate-600">
            Date range
            <select
              value={rangePreset}
              onChange={(event) => setRangePreset(event.target.value as DashboardRangePreset)}
              className="mt-1 w-36 rounded-md border border-slate-300 px-2 py-1.5 text-sm text-slate-900"
            >
              <option value="default">Backend default</option>
              <option value="last_24h">Last 24h</option>
              <option value="last_7d">Last 7 days</option>
              <option value="last_30d">Last 30 days</option>
            </select>
          </label>
          <button
            type="button"
            onClick={applyScope}
            disabled={isPending}
            className="rounded-md border border-slate-300 bg-slate-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-60"
          >
            {isPending ? "Applying..." : "Apply"}
          </button>
        </div>
      </div>
    </nav>
  );
}
