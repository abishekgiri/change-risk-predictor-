import { backendFetch } from "@/lib/backend";
import { resolveTenantId } from "@/lib/tenant";
import { NextResponse } from "next/server";

export async function POST(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const tenantId = resolveTenantId(searchParams.get("tenant_id") ?? undefined);
    const result = await backendFetch<{ portal_url: string }>(
      "/billing/portal",
      {
        method: "POST",
        query: { tenant_id: tenantId },
      },
    );
    return NextResponse.json(result.data);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Portal session failed";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
