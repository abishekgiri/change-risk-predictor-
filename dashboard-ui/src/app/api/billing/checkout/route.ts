import { backendFetch } from "@/lib/backend";
import { resolveTenantId } from "@/lib/tenant";
import { NextResponse } from "next/server";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { searchParams } = new URL(request.url);
    const tenantId = resolveTenantId(searchParams.get("tenant_id") ?? undefined);
    const result = await backendFetch<{ checkout_url: string; session_id: string }>(
      "/billing/checkout",
      {
        method: "POST",
        body: JSON.stringify({ plan: body.plan }),
        query: { tenant_id: tenantId },
      },
    );
    return NextResponse.json(result.data);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Checkout failed";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
