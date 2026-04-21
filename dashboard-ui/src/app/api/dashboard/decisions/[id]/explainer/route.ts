import { NextRequest } from "next/server";

import { proxyGet } from "@/lib/proxy";

export async function GET(
  request: NextRequest,
  context: { params: Promise<{ id: string }> },
) {
  const params = await context.params;
  const path = `/dashboard/decisions/${encodeURIComponent(params.id)}/explainer`;
  return proxyGet(request, path, ["tenant_id", "from", "to"]);
}
