import { TenantAdminPanel } from "@/components/TenantAdminPanel";
import { resolveDashboardScope } from "@/lib/dashboard-scope";

export const dynamic = "force-dynamic";

export default async function TenantAdminPage({
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
  return <TenantAdminPanel defaultTenantId={scope.tenantId} />;
}
