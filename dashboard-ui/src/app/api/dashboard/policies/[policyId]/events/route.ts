import { NextRequest, NextResponse } from "next/server";

import { backendFetch } from "@/lib/backend";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ policyId: string }> },
) {
  try {
    const { policyId } = await params;
    const tenantId = request.nextUrl.searchParams.get("tenant_id") || undefined;
    const { data } = await backendFetch(`/policies/${policyId}/events`, {
      method: "GET",
      query: { tenant_id: tenantId },
    });
    return NextResponse.json(data);
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Request failed" },
      { status: 500 },
    );
  }
}
