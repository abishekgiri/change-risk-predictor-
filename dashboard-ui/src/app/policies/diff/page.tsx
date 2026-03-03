import { PolicyDiffWorkbench } from "@/components/PolicyDiffWorkbench";
import { resolveTenantId } from "@/lib/tenant";

export default function PolicyDiffPage({
  searchParams,
}: {
  searchParams: { tenant_id?: string | string[] };
}) {
  const tenantId = resolveTenantId(searchParams.tenant_id);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-slate-900">Policy Diff</h1>
        <p className="mt-1 text-sm text-slate-600">
          Compare active vs staged policy contracts for tenant: {tenantId}
        </p>
      </div>
      <PolicyDiffWorkbench tenantId={tenantId} />
    </div>
  );
}
