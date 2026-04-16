import { NextRequest, NextResponse } from "next/server";

import { backendFetch } from "@/lib/backend";

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ tenant_id: string }> },
) {
  try {
    const { tenant_id } = await params;
    const { data } = await backendFetch(`/ops/tenant-health/${encodeURIComponent(tenant_id)}`, {
      method: "GET",
    });
    return NextResponse.json(data);
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Request failed" },
      { status: 500 },
    );
  }
}
