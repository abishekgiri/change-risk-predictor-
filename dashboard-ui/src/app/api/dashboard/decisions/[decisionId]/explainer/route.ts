import { NextRequest } from "next/server";

import { proxyGet } from "@/lib/proxy";

export async function GET(
  request: NextRequest,
  { params }: { params: { decisionId: string } },
) {
  const path = `/dashboard/decisions/${encodeURIComponent(params.decisionId)}/explainer`;
  return proxyGet(request, path, ["tenant_id"]);
}
