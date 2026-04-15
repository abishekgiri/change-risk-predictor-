import { backendFetch } from "@/lib/backend";
import { resolveTenantId } from "@/lib/tenant";
import { NextResponse } from "next/server";

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const tenantId = resolveTenantId(searchParams.get("tenant_id") ?? undefined);
    const result = await backendFetch<{ authorize_url: string }>(
      "/integrations/jira/oauth/authorize",
      { query: { tenant_id: tenantId } },
    );
    return NextResponse.json(result.data);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to generate authorize URL";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
