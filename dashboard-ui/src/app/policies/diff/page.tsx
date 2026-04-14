import { PolicyDiffWorkbench } from "@/components/PolicyDiffWorkbench";
import { resolveDashboardScope } from "@/lib/dashboard-scope";

export const dynamic = "force-dynamic";

export default async function PolicyDiffPage({
  searchParams,
}: {
  searchParams: Promise<{
    tenant_id?: string | string[];
    from?: string | string[];
    to?: string | string[];
    window_days?: string | string[];
  }>;
}) {
  const resolvedSearchParams = await searchParams;
  const scope = resolveDashboardScope(resolvedSearchParams);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-slate-900">Policy Changes</h1>
        <p className="mt-1 text-sm text-slate-600">
          Compare active vs staged policy controls for tenant: {scope.tenantId}
        </p>
      </div>
      <PolicyDiffWorkbench tenantId={scope.tenantId} fromTs={scope.fromTs} toTs={scope.toTs} />
    </div>
  );
}
