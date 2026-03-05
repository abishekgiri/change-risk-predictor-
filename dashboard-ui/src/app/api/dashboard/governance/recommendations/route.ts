import { NextRequest } from "next/server";

import { proxyGet } from "@/lib/proxy";

export async function GET(request: NextRequest) {
  return proxyGet(request, "/governance/recommendations", [
    "tenant_id",
    "status",
    "limit",
    "lookback_days",
    "refresh",
  ]);
}
