import { NextRequest } from "next/server";

import { proxyGet } from "@/lib/proxy";

export async function GET(request: NextRequest) {
  return proxyGet(request, "/dashboard/metrics/drilldown", [
    "tenant_id",
    "metric",
    "from",
    "to",
    "window_days",
    "limit",
  ]);
}
