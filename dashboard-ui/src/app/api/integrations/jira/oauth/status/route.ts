import { backendFetch } from "@/lib/backend";
import { resolveTenantId } from "@/lib/tenant";
import { NextResponse } from "next/server";

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const tenantId = resolveTenantId(searchParams.get("tenant_id") ?? undefined);
    const result = await backendFetch<{ connected: boolean; site_url: string | null; connected_at: string | null }>(
      "/integrations/jira/oauth/status",
      { query: { tenant_id: tenantId } },
    );
    return NextResponse.json(result.data);
  } catch {
    return NextResponse.json({ connected: false, site_url: null, connected_at: null });
  }
}
