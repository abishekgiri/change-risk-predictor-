import { backendFetch } from "@/lib/backend";
import { resolveTenantId } from "@/lib/tenant";
import { NextResponse } from "next/server";

export async function POST(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const tenantId = resolveTenantId(searchParams.get("tenant_id") ?? undefined);
    await backendFetch("/integrations/jira/oauth/disconnect", {
      method: "POST",
      query: { tenant_id: tenantId },
    });
    return NextResponse.json({ ok: true });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Disconnect failed";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
