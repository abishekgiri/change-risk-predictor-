import { NextRequest } from "next/server";

import { proxyGet } from "@/lib/proxy";

export async function GET(request: NextRequest) {
  return proxyGet(request, "/audit/evidence-graph/search", [
    "tenant_id",
    "status",
    "has_approval",
    "policy_hash",
    "actor",
    "workflow_id",
    "days",
    "limit",
  ]);
}
